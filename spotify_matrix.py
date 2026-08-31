#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
from io import BytesIO
import json
import os
import secrets
import threading
import time
import urllib.parse
import urllib.request
from email.message import Message
from urllib.error import HTTPError
import webbrowser
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

from PIL import Image, ImageDraw, ImageOps

try:
    from dotenv import load_dotenv
except ImportError:
    def load_dotenv() -> None:
        return None


AUTH_URL = "https://accounts.spotify.com/authorize"
TOKEN_URL = "https://accounts.spotify.com/api/token"
CURRENTLY_PLAYING_URL = "https://api.spotify.com/v1/me/player/currently-playing"
SCOPE = "user-read-currently-playing"


@dataclass
class PlaybackArt:
    key: str
    image_url: str
    is_playing: bool


@dataclass
class SharedPlaybackState:
    art_key: str | None = None
    image_url: str | None = None
    image: Image.Image | None = None
    is_playing: bool = False


@dataclass
class HttpResponse:
    status: int
    headers: Message
    body: bytes

    def json(self) -> dict[str, Any]:
        return json.loads(self.body.decode("utf-8"))


def http_request(
    method: str,
    url: str,
    *,
    params: dict[str, str] | None = None,
    data: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 10,
) -> HttpResponse:
    if params:
        separator = "&" if urllib.parse.urlparse(url).query else "?"
        url = f"{url}{separator}{urllib.parse.urlencode(params)}"

    encoded_data = urllib.parse.urlencode(data).encode("utf-8") if data else None
    request = urllib.request.Request(
        url,
        data=encoded_data,
        headers=headers or {},
        method=method,
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return HttpResponse(response.status, response.headers, response.read())
    except HTTPError as exc:
        return HttpResponse(exc.code, exc.headers, exc.read())


def raise_http_error(response: HttpResponse, context: str) -> None:
    body = response.body.decode("utf-8", errors="replace")
    raise RuntimeError(f"{context} failed with HTTP {response.status}: {body}")


class SpotifyClient:
    def __init__(
        self,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        token_cache: Path,
        open_browser: bool,
    ) -> None:
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.token_cache = token_cache
        self.open_browser = open_browser
        self.token = self._load_token()

    def get_currently_playing(self) -> dict[str, Any] | None:
        token = self._valid_access_token()
        response = http_request(
            "GET",
            CURRENTLY_PLAYING_URL,
            params={"additional_types": "track,episode"},
            headers={"Authorization": f"Bearer {token}"},
            timeout=10,
        )

        if response.status == 204:
            return None
        if response.status == 401:
            self._refresh_access_token()
            return self.get_currently_playing()
        if response.status == 429:
            retry_after = int(response.headers.get("Retry-After", "5"))
            time.sleep(max(retry_after, 1))
            return None
        if response.status != 200:
            raise_http_error(response, "Spotify currently-playing request")

        return response.json()

    def authorize(self) -> None:
        self._valid_access_token()

    def _valid_access_token(self) -> str:
        if not self.token:
            self.token = self._authorize()

        if time.time() >= float(self.token.get("expires_at", 0)):
            self._refresh_access_token()

        return str(self.token["access_token"])

    def _load_token(self) -> dict[str, Any] | None:
        if not self.token_cache.exists():
            return None

        with self.token_cache.open("r", encoding="utf-8") as token_file:
            return json.load(token_file)

    def _save_token(self, token: dict[str, Any]) -> None:
        self.token_cache.parent.mkdir(parents=True, exist_ok=True)
        token["expires_at"] = time.time() + int(token.get("expires_in", 3600)) - 60

        previous_refresh_token = self.token.get("refresh_token") if self.token else None
        if previous_refresh_token and "refresh_token" not in token:
            token["refresh_token"] = previous_refresh_token

        with self.token_cache.open("w", encoding="utf-8") as token_file:
            json.dump(token, token_file, indent=2)

        self.token = token

    def _authorize(self) -> dict[str, Any]:
        state = secrets.token_urlsafe(18)
        parsed_redirect = urllib.parse.urlparse(self.redirect_uri)
        if parsed_redirect.hostname not in {"127.0.0.1", "localhost"}:
            raise RuntimeError("This script expects a localhost Spotify redirect URI.")

        callback = LocalCallbackServer(
            host=parsed_redirect.hostname or "127.0.0.1",
            port=parsed_redirect.port or 80,
            path=parsed_redirect.path or "/callback",
            expected_state=state,
        )

        query = urllib.parse.urlencode(
            {
                "client_id": self.client_id,
                "response_type": "code",
                "redirect_uri": self.redirect_uri,
                "scope": SCOPE,
                "state": state,
            }
        )
        auth_url = f"{AUTH_URL}?{query}"

        print("Authorize Spotify in your browser:")
        print(auth_url)
        if self.open_browser:
            webbrowser.open(auth_url)

        code = callback.wait_for_code()
        token = self._post_token(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self.redirect_uri,
            }
        )
        self._save_token(token)
        return token

    def _refresh_access_token(self) -> None:
        refresh_token = self.token.get("refresh_token") if self.token else None
        if not refresh_token:
            self.token = self._authorize()
            return

        token = self._post_token(
            {
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
            }
        )
        self._save_token(token)

    def _post_token(self, data: dict[str, str]) -> dict[str, Any]:
        credentials = f"{self.client_id}:{self.client_secret}".encode("utf-8")
        basic_auth = base64.b64encode(credentials).decode("ascii")
        response = http_request(
            "POST",
            TOKEN_URL,
            data=data,
            headers={
                "Authorization": f"Basic {basic_auth}",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            timeout=10,
        )
        if response.status != 200:
            raise_http_error(response, "Spotify token request")
        return response.json()


class LocalCallbackServer:
    def __init__(self, host: str, port: int, path: str, expected_state: str) -> None:
        self.code: str | None = None
        self.error: str | None = None
        self.state_error: str | None = None
        self.path = path
        self.expected_state = expected_state

        parent = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                parsed = urllib.parse.urlparse(self.path)
                params = urllib.parse.parse_qs(parsed.query)

                if parsed.path != parent.path:
                    self.send_response(404)
                    self.end_headers()
                    self.wfile.write(b"Wrong callback path.")
                    return

                returned_state = params.get("state", [""])[0]
                if returned_state != parent.expected_state:
                    parent.state_error = "Spotify callback state did not match."
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b"State mismatch.")
                    return

                if "error" in params:
                    parent.error = params["error"][0]
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b"Spotify authorization failed.")
                    return

                parent.code = params.get("code", [None])[0]
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"Spotify authorization complete. You can close this tab.")

            def log_message(self, format: str, *args: Any) -> None:
                return

        self.server = HTTPServer((host, port), Handler)

    def wait_for_code(self) -> str:
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        try:
            while not self.code and not self.error and not self.state_error:
                time.sleep(0.1)
        finally:
            self.server.shutdown()
            self.server.server_close()

        if self.state_error:
            raise RuntimeError(self.state_error)
        if self.error:
            raise RuntimeError(f"Spotify authorization failed: {self.error}")
        if not self.code:
            raise RuntimeError("Spotify authorization did not return a code.")
        return self.code


class MatrixDisplay:
    def __init__(self, args: argparse.Namespace) -> None:
        try:
            from rgbmatrix import RGBMatrix, RGBMatrixOptions
        except ImportError as exc:
            raise RuntimeError(
                "The rgbmatrix Python bindings are not installed. "
                "Install hzeller/rpi-rgb-led-matrix on the Pi, or run with --mock-output."
            ) from exc

        options = RGBMatrixOptions()
        options.rows = args.rows
        options.cols = args.cols
        options.chain_length = args.chain_length
        options.parallel = args.parallel
        options.brightness = args.brightness
        options.gpio_slowdown = args.gpio_slowdown
        options.hardware_mapping = args.hardware_mapping
        options.pwm_bits = args.pwm_bits
        options.limit_refresh_rate_hz = args.limit_refresh_rate_hz
        options.disable_hardware_pulsing = args.no_hardware_pulse

        options.drop_privileges = False

        self.matrix = RGBMatrix(options=options)
        self.canvas = self.matrix.CreateFrameCanvas()

    def show(self, image: Image.Image) -> None:
        self.canvas.SetImage(image.convert("RGB"))
        self.canvas = self.matrix.SwapOnVSync(self.canvas)

    def clear(self) -> None:
        self.matrix.Clear()

class MockDisplay:
    def __init__(self, output: Path) -> None:
        self.output = output
        self.output.parent.mkdir(parents=True, exist_ok=True)

    def show(self, image: Image.Image) -> None:
        image.save(self.output)

    def clear(self) -> None:
        return


def demo_album_art(size: int) -> Image.Image:
    image = Image.new("RGB", (size, size), (18, 18, 18))
    draw = ImageDraw.Draw(image)
    draw.rectangle((0, 0, size // 2, size // 2), fill=(238, 70, 60))
    draw.rectangle((size // 2, 0, size, size // 2), fill=(245, 180, 40))
    draw.rectangle((0, size // 2, size // 2, size), fill=(35, 150, 235))
    draw.rectangle((size // 2, size // 2, size, size), fill=(65, 185, 95))
    draw.line((0, 0, size, size), fill=(255, 255, 255), width=max(2, size // 18))
    draw.line((size, 0, 0, size), fill=(0, 0, 0), width=max(2, size // 22))
    return image


def playback_art_from_response(playback: dict[str, Any] | None) -> PlaybackArt | None:
    if not playback:
        return None

    item = playback.get("item")
    if not item:
        return None

    item_type = item.get("type")
    if item_type == "track":
        images = item.get("album", {}).get("images", [])
    else:
        images = item.get("images", [])

    if not images:
        return None

    image = max(images, key=lambda candidate: candidate.get("width") or 0)
    item_id = item.get("id") or item.get("uri") or image["url"]
    return PlaybackArt(
        key=str(item_id),
        image_url=image["url"],
        is_playing=bool(playback.get("is_playing")),
    )


def download_image(url: str) -> Image.Image:
    import requests

    response = requests.get(url, timeout=15)
    response.raise_for_status()
    return Image.open(BytesIO(response.content)).convert("RGB")

def prepare_album_art(art: Image.Image, size: int) -> Image.Image:
    margin = max(2, size // 32)
    disc_size = size - margin * 2

    return ImageOps.fit(
        art,
        (disc_size, disc_size),
        method=Image.Resampling.LANCZOS,
    )

def prepare_album_art(art: Image.Image, size: int) -> Image.Image:
    """
    Resize the album art once when the song/album changes.
    """
    margin = max(2, size // 32)
    disc_size = size - margin * 2

    return ImageOps.fit(
        art,
        (disc_size, disc_size),
        method=Image.Resampling.LANCZOS,
    )

def add_pause_overlay(image: Image.Image) -> Image.Image:
    paused = image.copy().convert("RGBA")

    overlay = Image.new("RGBA", paused.size, (0, 0, 0, 0))
    draw = ImageDraw.Draw(overlay)

    size = paused.width
    center = size // 2

    # Dark translucent circle behind pause symbol
    radius = size // 5
    draw.ellipse(
        (
            center - radius,
            center - radius,
            center + radius,
            center + radius,
        ),
        fill=(0, 0, 0, 170),
    )

    # Pause bars
    bar_width = max(3, size // 14)
    bar_height = size // 4
    gap = size // 18

    top = center - bar_height // 2
    bottom = center + bar_height // 2

    draw.rectangle(
        (
            center - gap - bar_width,
            top,
            center - gap,
            bottom,
        ),
        fill=(255, 255, 255, 255),
    )

    draw.rectangle(
        (
            center + gap,
            top,
            center + gap + bar_width,
            bottom,
        ),
        fill=(255, 255, 255, 255),
    )

    return Image.alpha_composite(paused, overlay).convert("RGB")

def render_record(
    art_square: Image.Image | None,
    angle: float,
    size: int
) -> Image.Image:
    """
    Render one already-resized album-art frame at a given angle.
    """

    frame = Image.new(
        "RGBA",
        (size, size),
        (0, 0, 0, 255)
    )

    if art_square is None:
        return frame.convert("RGB")

    margin = max(2, size // 32)
    disc_size = size - margin * 2

    # Rotate the small, already-resized album art
    rotated = art_square.rotate(
        angle,
        resample=Image.Resampling.BICUBIC
    )

    # Circular mask
    disc_mask = Image.new(
        "L",
        (disc_size, disc_size),
        0
    )

    mask_draw = ImageDraw.Draw(disc_mask)

    mask_draw.ellipse(
        (0, 0, disc_size - 1, disc_size - 1),
        fill=255
    )

    # Paste circular album art onto frame
    frame.paste(
        rotated.convert("RGBA"),
        (margin, margin),
        disc_mask
    )

    # Draw record details
    draw = ImageDraw.Draw(frame, "RGBA")

    outer = (
        margin,
        margin,
        size - margin - 1,
        size - margin - 1
    )

    draw.ellipse(
        outer,
        outline=(6, 6, 6, 255),
        width=max(1, size // 32)
    )

    center = size // 2

    label_radius = max(5, size // 11)
    hole_radius = max(2, size // 25)

    # Center label
    draw.ellipse(
        (
            center - label_radius,
            center - label_radius,
            center + label_radius,
            center + label_radius,
        ),
        fill=(16, 16, 16, 210),
        outline=(220, 220, 220, 90),
    )

    # Center hole
    draw.ellipse(
        (
            center - hole_radius,
            center - hole_radius,
            center + hole_radius,
            center + hole_radius,
        ),
        fill=(0, 0, 0, 255),
    )

    return frame.convert("RGB")


def prepare_rotation_frames(
    art: Image.Image,
    size: int,
    num_frames: int = 60
) -> list[Image.Image]:
    """
    Generate all rotated record images once.

    The main animation loop can then simply select a frame
    instead of performing Pillow rotations every frame.
    """

    prepared_art = prepare_album_art(art, size)

    frames = []

    for i in range(num_frames):
        angle = 360.0 * i / num_frames

        frame = render_record(
            prepared_art,
            angle,
            size
        )

        frames.append(frame)

    return frames


def render_idle(size: int) -> Image.Image:
    frame = Image.new("RGB", (size, size), (0, 0, 0))
    draw = ImageDraw.Draw(frame)
    margin = max(2, size // 32)
    draw.ellipse((margin, margin, size - margin - 1, size - margin - 1), outline=(55, 55, 55), width=2)
    center = size // 2
    radius = max(3, size // 18)
    draw.ellipse((center - radius, center - radius, center + radius, center + radius), fill=(18, 18, 18))
    return frame


def render_test_pattern(size: int, offset: int) -> Image.Image:
    frame = Image.new("RGB", (size, size), (0, 0, 0))
    draw = ImageDraw.Draw(frame)
    colors = (
        (255, 0, 0),
        (255, 160, 0),
        (255, 255, 0),
        (0, 255, 0),
        (0, 120, 255),
        (80, 0, 255),
        (255, 255, 255),
        (0, 0, 0),
    )
    stripe_width = max(1, size // len(colors))
    for index, color in enumerate(colors):
        x0 = (index * stripe_width + offset) % size
        draw.rectangle((x0, 0, min(size - 1, x0 + stripe_width - 1), size - 1), fill=color)
        if x0 + stripe_width > size:
            draw.rectangle((0, 0, (x0 + stripe_width) % size, size - 1), fill=color)
    draw.rectangle((0, 0, size - 1, size - 1), outline=(255, 255, 255))
    return frame


def poll_spotify(
    spotify: SpotifyClient,
    state: SharedPlaybackState,
    state_lock: threading.Lock,
    stop_event: threading.Event,
    poll_seconds: float,
) -> None:
    last_status: str | None = None

    while not stop_event.is_set():
        try:
            playback = spotify.get_currently_playing()
            art = playback_art_from_response(playback)

            if art:
                with state_lock:
                    needs_download = art.key != state.art_key or art.image_url != state.image_url

                image = download_image(art.image_url) if needs_download else None

                with state_lock:
                    state.art_key = art.key
                    state.image_url = art.image_url
                    state.is_playing = art.is_playing
                    if image is not None:
                        state.image = image

                status = f"art found, is_playing={art.is_playing}"
            else:
                with state_lock:
                    state.art_key = None
                    state.image_url = None
                    state.image = None
                    state.is_playing = False
                status = "no currently playing item"

            if status != last_status:
                print(f"Spotify: {status}", flush=True)
                last_status = status
        except Exception as exc:
            print(f"Spotify poll failed: {exc}", flush=True)

        stop_event.wait(poll_seconds)


def run(args: argparse.Namespace) -> None:
    if args.preview_frames:
        render_preview_frames(args.preview_frames)
        return

    load_dotenv()

    client_id = os.environ.get("SPOTIFY_CLIENT_ID")
    client_secret = os.environ.get("SPOTIFY_CLIENT_SECRET")
    redirect_uri = os.environ.get("SPOTIFY_REDIRECT_URI", "http://127.0.0.1:8888/callback")

    missing = [
        name
        for name, value in (
            ("SPOTIFY_CLIENT_ID", client_id),
            ("SPOTIFY_CLIENT_SECRET", client_secret),
            ("SPOTIFY_REDIRECT_URI", redirect_uri),
        )
        if not value
    ]
    if missing:
        raise SystemExit(f"Missing required environment values: {', '.join(missing)}")

    spotify = SpotifyClient(
        client_id=client_id or "",
        client_secret=client_secret or "",
        redirect_uri=redirect_uri,
        token_cache=args.token_cache,
        open_browser=not args.no_browser,
    )

    if args.auth_only:
        spotify.authorize()
        print(f"Spotify token cached at {args.token_cache}")
        return

    display: MatrixDisplay | MockDisplay
    if args.mock_output:
        display = MockDisplay(args.mock_output)
    else:
        display = MatrixDisplay(args)

    size = min(args.rows, args.cols)

    if args.test_pattern:
        try:
            offset = 0
            while True:
                display.show(render_test_pattern(size, offset))
                offset = (offset + 1) % size
                time.sleep(1.0 / args.fps)
        except KeyboardInterrupt:
            pass
        finally:
            display.clear()
        return

    idle = render_idle(size)
    playback_state = SharedPlaybackState()
    playback_lock = threading.Lock()
    stop_event = threading.Event()
    poll_thread = threading.Thread(
        target=poll_spotify,
        args=(spotify, playback_state, playback_lock, stop_event, args.poll_seconds),
        daemon=True,
    )
    poll_thread.start()

    angle = 0.0
    last_frame = time.monotonic()

    # ---------------------------------------------------------
    # Pre-rendered rotation frame cache
    # ---------------------------------------------------------

    last_art_image = None
    rotation_frames = None
    paused_frames = None

    # Number of discrete angles in one full rotation.
    # 60 is a good starting point for a 64x64 display.
    NUM_ROTATION_FRAMES = 60


    # ---------------------------------------------------------
    # Performance counters
    # ---------------------------------------------------------

    fps_frame_count = 0
    fps_start_time = time.monotonic()

    total_lock_time = 0.0
    total_render_time = 0.0
    total_display_time = 0.0


    try:
        while True:
            frame_start = time.monotonic()


            # =================================================
            # Get Spotify playback state
            # =================================================

            lock_start = time.monotonic()

            with playback_lock:
                current_art_image = playback_state.image
                is_playing = playback_state.is_playing

            lock_time = time.monotonic() - lock_start
            total_lock_time += lock_time


            # =================================================
            # Check whether album artwork changed
            # =================================================

            # =================================================
            # Check whether album artwork changed
            # =================================================

            if current_art_image is not last_art_image:

                if current_art_image is not None:
                    print(
                        f"Preparing {NUM_ROTATION_FRAMES} "
                        f"rotation frames..."
                    )

                    prepare_start = time.monotonic()

                    rotation_frames = prepare_rotation_frames(
                        current_art_image,
                        size,
                        NUM_ROTATION_FRAMES
                    )

                    # Create paused versions of every frame
                    paused_frames = [
                        add_pause_overlay(frame)
                        for frame in rotation_frames
                    ]

                    prepare_elapsed = (
                            time.monotonic()
                            - prepare_start
                    )

                    print(
                        f"Rotation frames ready in "
                        f"{prepare_elapsed:.2f} seconds"
                    )

                else:
                    rotation_frames = None
                    paused_frames = None

                last_art_image = current_art_image


            # =================================================
            # Calculate rotation angle
            # =================================================

            now = time.monotonic()

            delta = now - last_frame

            last_frame = now

            if (
                is_playing
                and rotation_frames is not None
            ):
                angle = (
                    angle
                    - 360.0
                    * (args.rpm / 60.0)
                    * delta
                ) % 360.0


            # =================================================
            # Select already-rendered frame
            # =================================================

            render_start = time.monotonic()

            if rotation_frames is not None:

                frame_index = int(
                    (angle / 360.0)
                    * len(rotation_frames)
                ) % len(rotation_frames)

                if is_playing:
                    image = rotation_frames[frame_index]
                else:
                    image = paused_frames[frame_index]

            else:
                image = idle

            render_time = (
                time.monotonic()
                - render_start
            )

            total_render_time += render_time


            # =================================================
            # Send frame to LED matrix
            # =================================================

            display_start = time.monotonic()

            display.show(image)

            display_time = (
                time.monotonic()
                - display_start
            )

            total_display_time += display_time


            # =================================================
            # --once support
            # =================================================

            if args.once:
                break


            # =================================================
            # FPS / performance output
            # =================================================

            fps_frame_count += 1

            elapsed = (
                time.monotonic()
                - fps_start_time
            )

            if elapsed >= 1.0:

                actual_fps = (
                    fps_frame_count
                    / elapsed
                )

                avg_lock_ms = (
                    total_lock_time
                    / fps_frame_count
                ) * 1000

                avg_render_ms = (
                    total_render_time
                    / fps_frame_count
                ) * 1000


                avg_display_ms = (
                    total_display_time
                    / fps_frame_count
                ) * 1000

                total_measured_ms = (
                    avg_lock_ms
                    + avg_render_ms
                    + avg_display_ms
                )

                print(
                    f"FPS: {actual_fps:.1f} | "
                    f"Lock: {avg_lock_ms:.1f} ms | "
                    f"Render: {avg_render_ms:.1f} ms | "
                    f"Display: {avg_display_ms:.1f} ms | "
                    f"Measured: {total_measured_ms:.1f} ms"
                )


                # Reset measurements

                fps_frame_count = 0

                fps_start_time = (
                    time.monotonic()
                )

                total_lock_time = 0.0
                total_render_time = 0.0
                total_display_time = 0.0


            # =================================================
            # Maintain requested FPS
            # =================================================

            sleep_for = max(
                0.0,
                (1.0 / args.fps)
                - (
                    time.monotonic()
                    - frame_start
                )
            )

            time.sleep(sleep_for)


    except KeyboardInterrupt:
        pass


    finally:
        stop_event.set()
        poll_thread.join(timeout=1)
        display.clear()


def positive_float(value: str) -> float:
    parsed = float(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def render_preview_frames(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    art = demo_album_art(96)
    for index, angle in enumerate((0, 45, 90, 135)):
        render_record(art, angle, 64).save(directory / f"album-disk-{index:02d}.png")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Spin Spotify album art on a 64x64 RGB matrix.")
    parser.add_argument("--rows", type=int, default=64)
    parser.add_argument("--cols", type=int, default=64)
    parser.add_argument("--chain-length", type=int, default=1)
    parser.add_argument("--parallel", type=int, default=1)
    parser.add_argument("--brightness", type=int, default=65)
    parser.add_argument("--gpio-slowdown", type=int, default=1)
    parser.add_argument("--hardware-mapping", default="adafruit-hat")
    parser.add_argument("--pwm-bits", type=int, default=11)
    parser.add_argument("--limit-refresh-rate-hz", type=int, default=120)
    parser.add_argument(
        "--no-hardware-pulse",
        action="store_true",
        help="Avoid Pi onboard sound conflict at the cost of more possible flicker.",
    )
    parser.add_argument("--poll-seconds", type=positive_float, default=2.0)
    parser.add_argument("--fps", type=positive_float, default=20.0)
    parser.add_argument("--rpm", type=positive_float, default=10.0)
    parser.add_argument("--token-cache", type=Path, default=Path(".cache/spotify_token.json"))
    parser.add_argument("--mock-output", type=Path, help="Write the current frame PNG instead of using RGB matrix hardware.")
    parser.add_argument("--preview-frames", type=Path, help="Render sample spinning-album-art disk frames and exit.")
    parser.add_argument("--auth-only", action="store_true", help="Authorize Spotify, cache the token, and exit without using the matrix.")
    parser.add_argument("--test-pattern", action="store_true", help="Show a bright moving color test pattern without using Spotify.")
    parser.add_argument("--once", action="store_true", help="Render one frame and exit.")
    parser.add_argument("--no-browser", action="store_true", help="Print the Spotify auth URL without trying to open a browser.")
    return parser


if __name__ == "__main__":
    run(build_parser().parse_args())
