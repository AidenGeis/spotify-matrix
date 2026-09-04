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
import math
import urllib.parse
import urllib.request
from email.message import Message
from urllib.error import HTTPError
import webbrowser
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

from PIL import Image, ImageDraw, ImageOps, ImageChops, ImageFont

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
class WeatherState:
    temperature: float | None = None
    weather_code: int | None = None
    high: float | None = None
    low: float | None = None
    is_day: bool = True

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

    # =================================================
    # Outer rings
    # =================================================

    outer = (
        margin,
        margin,
        size - margin - 1,
        size - margin - 1
    )

    pink_outer = (
        outer[0] - 1,
        outer[1] - 1,
        outer[2] + 1,
        outer[3] + 1
    )

    # Thin pink outer ring
    draw.ellipse(
        pink_outer,
        outline=(255, 105, 180, 255),
        width=2
    )

    # White outer ring
    draw.ellipse(
        outer,
        outline=(255, 255, 255, 255),
        width=1
    )



    # =================================================
    # Center circle
    # =================================================

    center = size // 2

    label_radius = max(2, size // 15)
    hole_radius = max(2, size // 25)

    # Pink center
    draw.ellipse(
        (
            center - label_radius,
            center - label_radius,
            center + label_radius,
            center + label_radius,
        ),
        fill=(255, 105, 180, 255)
    )

    # White ring farther inward
    white_radius = label_radius

    draw.ellipse(
        (
            center - white_radius,
            center - white_radius,
            center + white_radius,
            center + white_radius,
        ),
        outline=(255, 255, 255, 255),
        width=1
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

    # =================================================
    # Pink hearts in the four corners
    # =================================================

    # Top-right: one normal heart
    draw_heart(
        draw,
        size - 6,
        5,
        size=3
    )

    # Bottom-left: one normal heart
    draw_heart(
        draw,
        5,
        size - 6,
        size=3
    )

    # =================================================
    # Top-left: two smaller hearts
    # =================================================

    draw_heart(
        draw,
        4,
        4,
        size=2
    )

    draw_heart(
        draw,
        9,
        8,
        size=2
    )

    # =================================================
    # Bottom-right: two smaller hearts
    # Opposite diagonal from top-left
    # =================================================

    draw_heart(
        draw,
        size - 10,
        size - 5,
        size=2
    )

    draw_heart(
        draw,
        size - 5,
        size - 10,
        size=2
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

def prepare_shatter_frames(
    source: Image.Image,
    frame_count: int = 14
) -> list[Image.Image]:
    """
    Break the current CD into several large pieces and
    pre-render the complete shatter animation.
    """

    size = source.width
    center = size / 2

    source = source.convert("RGBA")

    # Large irregular pieces.
    # Coordinates are fractions of the entire image.
    piece_shapes = [
        # Top-left
        [
            (0.00, 0.00),
            (0.50, 0.00),
            (0.43, 0.34),
            (0.30, 0.49),
            (0.00, 0.39),
        ],

        # Top-right
        [
            (0.50, 0.00),
            (1.00, 0.00),
            (1.00, 0.40),
            (0.67, 0.43),
            (0.43, 0.34),
        ],

        # Left-middle
        [
            (0.00, 0.39),
            (0.30, 0.49),
            (0.43, 0.61),
            (0.28, 0.79),
            (0.00, 0.71),
        ],

        # Center
        [
            (0.43, 0.34),
            (0.67, 0.43),
            (0.63, 0.69),
            (0.43, 0.61),
            (0.30, 0.49),
        ],

        # Right-middle
        [
            (0.67, 0.43),
            (1.00, 0.40),
            (1.00, 0.73),
            (0.69, 0.79),
            (0.63, 0.69),
        ],

        # Bottom-left
        [
            (0.00, 0.71),
            (0.28, 0.79),
            (0.50, 1.00),
            (0.00, 1.00),
        ],

        # Bottom-right
        [
            (0.28, 0.79),
            (0.43, 0.61),
            (0.63, 0.69),
            (0.69, 0.79),
            (1.00, 0.73),
            (1.00, 1.00),
            (0.50, 1.00),
        ],
    ]

    rotations = [
        -18,
        16,
        -14,
        7,
        18,
        -15,
        14,
    ]

    pieces = []

    # Only shatter the circular CD itself.
    disc_mask = Image.new(
        "L",
        (size, size),
        0
    )

    disc_draw = ImageDraw.Draw(disc_mask)

    margin = max(2, size // 32)

    disc_draw.ellipse(
        (
            margin,
            margin,
            size - margin - 1,
            size - margin - 1,
        ),
        fill=255
    )

    # -------------------------------------------------
    # Extract each piece
    # -------------------------------------------------

    for index, normalized_points in enumerate(piece_shapes):

        points = [
            (
                int(x * size),
                int(y * size)
            )
            for x, y in normalized_points
        ]

        polygon_mask = Image.new(
            "L",
            (size, size),
            0
        )

        polygon_draw = ImageDraw.Draw(
            polygon_mask
        )

        polygon_draw.polygon(
            points,
            fill=255
        )

        # Intersection of:
        # irregular piece AND circular record.
        mask = ImageChops.multiply(
            polygon_mask,
            disc_mask
        )

        bbox = mask.getbbox()

        if bbox is None:
            continue

        piece = source.crop(bbox)
        piece_mask = mask.crop(bbox)

        piece.putalpha(piece_mask)

        piece_center_x = (
            bbox[0] + bbox[2]
        ) / 2

        piece_center_y = (
            bbox[1] + bbox[3]
        ) / 2

        dx = (
            piece_center_x
            - center
        )

        dy = (
            piece_center_y
            - center
        )

        distance = math.hypot(
            dx,
            dy
        )

        if distance > 0:
            direction_x = dx / distance
            direction_y = dy / distance
        else:
            direction_x = 0
            direction_y = -1

        # Different pieces travel slightly
        # different distances.
        travel = 8 + (index % 3) * 2

        pieces.append(
            {
                "image": piece,
                "bbox": bbox,
                "dx": direction_x * travel,
                "dy": direction_y * travel,
                "rotation": rotations[index],
            }
        )

    # -------------------------------------------------
    # Pre-render animation
    # -------------------------------------------------

    frames = []

    for frame_number in range(frame_count):

        if frame_count == 1:
            progress = 1.0
        else:
            progress = (
                frame_number
                / (frame_count - 1)
            )

        # Ease-out:
        # pieces move quickly at first,
        # then slow down.
        movement = (
            1.0
            - (1.0 - progress) ** 3
        )

        frame = Image.new(
            "RGBA",
            (size, size),
            (0, 0, 0, 255)
        )

        for piece_data in pieces:

            piece = piece_data["image"]
            bbox = piece_data["bbox"]

            rotation = (
                piece_data["rotation"]
                * movement
            )

            rotated_piece = piece.rotate(
                rotation,
                resample=Image.Resampling.BICUBIC,
                expand=True
            )

            x_offset = (
                piece_data["dx"]
                * movement
            )

            y_offset = (
                piece_data["dy"]
                * movement
            )

            # Slight gravity
            y_offset += (
                3
                * movement
                * movement
            )

            original_width = (
                bbox[2] - bbox[0]
            )

            original_height = (
                bbox[3] - bbox[1]
            )

            expansion_x = (
                rotated_piece.width
                - original_width
            ) / 2

            expansion_y = (
                rotated_piece.height
                - original_height
            ) / 2

            x = int(
                bbox[0]
                + x_offset
                - expansion_x
            )

            y = int(
                bbox[1]
                + y_offset
                - expansion_y
            )

            # Paste with its own alpha channel.
            # Negative coordinates are okay; Pillow
            # clips anything outside the display.
            frame.paste(
                rotated_piece,
                (x, y),
                rotated_piece
            )

        frames.append(
            frame.convert("RGB")
        )

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

def draw_heart(
    draw: ImageDraw.ImageDraw,
    x: int,
    y: int,
    size: int = 3
) -> None:
    """
    Draw a small pixel-friendly pink heart centered at (x, y).
    """

    pink = (255, 105, 180)

    # Left rounded part of heart
    draw.ellipse(
        (
            x - size,
            y - size,
            x,
            y
        ),
        fill=pink
    )

    # Right rounded part of heart
    draw.ellipse(
        (
            x,
            y - size,
            x + size,
            y
        ),
        fill=pink
    )

    # Bottom pointed part of heart
    draw.polygon(
        [
            (x - size, y - 1),
            (x + size, y - 1),
            (x, y + size),
        ],
        fill=pink
    )

def blend_with_black(
    image: Image.Image,
    amount: float
) -> Image.Image:
    """
    Darken an image.

    amount = 0.0 -> normal image
    amount = 1.0 -> completely black
    """

    amount = max(0.0, min(1.0, amount))

    black = Image.new(
        "RGB",
        image.size,
        (0, 0, 0)
    )

    return Image.blend(
        image.convert("RGB"),
        black,
        amount
    )

def render_clock(size: int) -> Image.Image:
    """
    Render a simple analog clock for the idle screen.
    """

    frame = Image.new(
        "RGB",
        (size, size),
        (0, 0, 0)
    )

    draw = ImageDraw.Draw(frame)

    center_x = size // 2
    center_y = size // 2

    radius = size // 2 - 3

    # =================================================
    # Outer clock circle
    # =================================================

    draw.ellipse(
        (
            center_x - radius,
            center_y - radius,
            center_x + radius,
            center_y + radius,
        ),
        outline=(180, 180, 180),
        width=2
    )


    # =================================================
    # Hour markers
    # =================================================

    for hour in range(12):

        angle = math.radians(
            hour * 30 - 90
        )

        # Make the 12, 3, 6, and 9 markers longer
        if hour % 3 == 0:
            inner_radius = radius - 6
            width = 2
        else:
            inner_radius = radius - 3
            width = 1

        outer_x = (
            center_x
            + math.cos(angle) * (radius - 2)
        )

        outer_y = (
            center_y
            + math.sin(angle) * (radius - 2)
        )

        inner_x = (
            center_x
            + math.cos(angle) * inner_radius
        )

        inner_y = (
            center_y
            + math.sin(angle) * inner_radius
        )

        draw.line(
            (
                int(inner_x),
                int(inner_y),
                int(outer_x),
                int(outer_y),
            ),
            fill=(220, 220, 220),
            width=width
        )


    # =================================================
    # Current time
    # =================================================

    current_time = time.localtime()

    hour = current_time.tm_hour % 12
    minute = current_time.tm_min


    # Hour hand includes minute progress
    hour_angle = math.radians(
        (
            hour
            + minute / 60.0
        ) * 30
        - 90
    )

    minute_angle = math.radians(
        minute * 6 - 90
    )


    # =================================================
    # Hour hand
    # =================================================

    hour_length = radius * 0.50

    hour_x = (
        center_x
        + math.cos(hour_angle)
        * hour_length
    )

    hour_y = (
        center_y
        + math.sin(hour_angle)
        * hour_length
    )

    draw.line(
        (
            center_x,
            center_y,
            int(hour_x),
            int(hour_y)
        ),
        fill=(255, 255, 255),
        width=3
    )


    # =================================================
    # Minute hand
    # =================================================

    minute_length = radius * 0.72

    minute_x = (
        center_x
        + math.cos(minute_angle)
        * minute_length
    )

    minute_y = (
        center_y
        + math.sin(minute_angle)
        * minute_length
    )

    draw.line(
        (
            center_x,
            center_y,
            int(minute_x),
            int(minute_y)
        ),
        fill=(200, 200, 200),
        width=2
    )

    # =================================================
    # Center pin
    # =================================================

    pin_radius = 2

    draw.ellipse(
        (
            center_x - pin_radius,
            center_y - pin_radius,
            center_x + pin_radius,
            center_y + pin_radius,
        ),
        fill=(255, 255, 255)
    )

    # =================================================
    # Pink hearts in the four corners
    # =================================================

    # Top-right: one normal heart
    draw_heart(
        draw,
        size - 6,
        5,
        size=3
    )

    # Bottom-left: one normal heart
    draw_heart(
        draw,
        5,
        size - 6,
        size=3
    )

    # =================================================
    # Top-left: two smaller hearts
    # =================================================

    draw_heart(
        draw,
        4,
        4,
        size=2
    )

    draw_heart(
        draw,
        9,
        8,
        size=2
    )

    # =================================================
    # Bottom-right: two smaller hearts
    # Opposite diagonal from top-left
    # =================================================

    draw_heart(
        draw,
        size - 10,
        size - 5,
        size=2
    )

    draw_heart(
        draw,
        size - 5,
        size - 10,
        size=2
    )

    return frame

def render_weather(
    size: int,
    temperature: float | None,
    weather_code: int | None,
    high: float | None,
    low: float | None,
    is_day: bool,
) -> Image.Image:

    frame = Image.new(
        "RGB",
        (size, size),
        (0, 0, 0)
    )

    draw = ImageDraw.Draw(frame)

    font = ImageFont.load_default()


    # =================================================
    # DATE
    # =================================================

    current_date = time.strftime(
        "%b %d"
    ).upper()

    bbox = draw.textbbox(
        (0, 0),
        current_date,
        font=font
    )

    text_width = (
        bbox[2] - bbox[0]
    )

    draw.text(
        (
            (size - text_width) // 2,
            1
        ),
        current_date,
        fill=(255, 105, 180),
        font=font
    )


    # =================================================
    # WEATHER NOT READY YET
    # =================================================

    if (
        temperature is None
        or weather_code is None
    ):

        text = "WEATHER"

        bbox = draw.textbbox(
            (0, 0),
            text,
            font=font
        )

        text_width = (
            bbox[2] - bbox[0]
        )

        draw.text(
            (
                (size - text_width) // 2,
                30
            ),
            text,
            fill=(180, 180, 180),
            font=font
        )

        return frame


    # =================================================
    # WEATHER ICON
    # =================================================

    draw_weather_icon(
        draw,
        int(weather_code),
        is_day
    )


    # =================================================
    # CURRENT TEMPERATURE
    # =================================================

    temperature_text = (
        f"{round(temperature)}F"
    )

    bbox = draw.textbbox(
        (0, 0),
        temperature_text,
        font=font
    )

    text_width = (
        bbox[2] - bbox[0]
    )

    draw.text(
        (
            (size - text_width) // 2,
            41
        ),
        temperature_text,
        fill=(255, 255, 255),
        font=font
    )


    # =================================================
    # HIGH / LOW
    # =================================================

    if (
        high is not None
        and low is not None
    ):

        high_low_text = (
            f"H: {round(high)} L: {round(low)}"
        )

        bbox = draw.textbbox(
            (0, 0),
            high_low_text,
            font=font
        )

        text_width = (
            bbox[2] - bbox[0]
        )

        draw.text(
            (
                (size - text_width) // 2,
                51
            ),
            high_low_text,
            fill=(210, 210, 210),
            font=font
        )


    return frame

def render_birthday(
    size: int,
) -> Image.Image:

    frame = Image.new(
        "RGB",
        (size, size),
        (0, 0, 0)
    )

    draw = ImageDraw.Draw(frame)

    font = ImageFont.load_default()


    # =================================================
    # HELPER FOR CENTERED TEXT
    # =================================================

    def centered_text(
        text,
        y,
        color
    ):

        bbox = draw.textbbox(
            (0, 0),
            text,
            font=font
        )

        text_width = (
            bbox[2] - bbox[0]
        )

        draw.text(
            (
                (size - text_width) // 2,
                y
            ),
            text,
            fill=color,
            font=font
        )


    # =================================================
    # BALLOON HELPER
    # =================================================

    def balloon(
        x,
        y,
        color,
        string_length=9
    ):

        # Balloon body
        draw.ellipse(
            (
                x - 4,
                y - 5,
                x + 4,
                y + 5
            ),
            fill=color
        )

        # Little knot
        draw.polygon(
            [
                (x - 2, y + 5),
                (x + 2, y + 5),
                (x, y + 8),
            ],
            fill=color
        )

        # String
        draw.line(
            (
                x,
                y + 8,
                x,
                y + 8 + string_length
            ),
            fill=(180, 180, 180),
            width=1
        )


    # =================================================
    # BALLOONS
    # =================================================

    balloon(
        6,
        7,
        (255, 105, 180),
        8
    )

    balloon(
        57,
        8,
        (120, 180, 255),
        8
    )

    balloon(
        7,
        48,
        (255, 80, 80),
        6
    )

    balloon(
        56,
        49,
        (200, 100, 255),
        6
    )


    # =================================================
    # BIRTHDAY MESSAGE
    # =================================================

    centered_text(
        "HAPPY",
        3,
        (255, 220, 80)
    )

    centered_text(
        "BIRTHDAY",
        14,
        (255, 105, 180)
    )

    centered_text(
        "ALAINA!",
        25,
        (255, 255, 255)
    )

    centered_text(
        "I LOVE",
        38,
        (255, 105, 180)
    )

    centered_text(
        "YOU!",
        49,
        (255, 255, 255)
    )

    return frame

def render_picture(
    image_path: str,
    size: int,
) -> Image.Image:

    image = Image.open(
        image_path
    ).convert("RGB")

    image = ImageOps.fit(
        image,
        (size, size),
        method=Image.Resampling.LANCZOS
    )

    return image

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

def fetch_weather(
    latitude: float,
    longitude: float
) -> dict[str, Any]:
    """
    Fetch current weather and today's high/low
    from Open-Meteo.
    """

    params = urllib.parse.urlencode(
        {
            "latitude": latitude,
            "longitude": longitude,

            "current": (
                "temperature_2m,"
                "weather_code,"
                "is_day"
            ),

            "daily": (
                "temperature_2m_max,"
                "temperature_2m_min"
            ),

            "temperature_unit": "fahrenheit",
            "timezone": "auto",
            "forecast_days": 1,
        }
    )

    url = (
        "https://api.open-meteo.com/v1/forecast?"
        + params
    )

    response = http_request(
        "GET",
        url,
        timeout=10
    )

    if response.status != 200:
        raise_http_error(
            response,
            "Weather request"
        )

    return response.json()


def poll_weather(
    weather_state: WeatherState,
    weather_lock: threading.Lock,
    stop_event: threading.Event,
    latitude: float,
    longitude: float,
    update_seconds: float,
) -> None:
    """
    Update weather information in the background.
    """

    while not stop_event.is_set():

        try:

            data = fetch_weather(
                latitude,
                longitude
            )

            current = data.get(
                "current",
                {}
            )

            daily = data.get(
                "daily",
                {}
            )

            high_values = daily.get(
                "temperature_2m_max",
                []
            )

            low_values = daily.get(
                "temperature_2m_min",
                []
            )

            with weather_lock:

                weather_state.temperature = (
                    current.get(
                        "temperature_2m"
                    )
                )

                weather_state.weather_code = (
                    current.get(
                        "weather_code"
                    )
                )

                weather_state.is_day = bool(
                    current.get(
                        "is_day",
                        1
                    )
                )

                if high_values:
                    weather_state.high = (
                        high_values[0]
                    )

                if low_values:
                    weather_state.low = (
                        low_values[0]
                    )

            print(
                "Weather updated: "
                f"{weather_state.temperature} F",
                flush=True
            )

        except Exception as exc:

            print(
                f"Weather update failed: {exc}",
                flush=True
            )

        stop_event.wait(
            update_seconds
        )

def draw_weather_icon(
    draw: ImageDraw.ImageDraw,
    code: int,
    is_day: bool,
) -> None:
    """
    Draw a simple weather icon suitable
    for a 64x64 RGB matrix.

    All icons are shifted down by 5 pixels.
    """

    y_offset = 8


    # =================================================
    # CLEAR
    # =================================================

    if code == 0:

        # Sun
        center_x = 32
        center_y = 15 + y_offset
        radius = 6

        draw.ellipse(
            (
                center_x - radius,
                center_y - radius,
                center_x + radius,
                center_y + radius,
            ),
            fill=(255, 210, 50)
        )

        # Sun rays
        for angle_degrees in range(
            0,
            360,
            45
        ):

            angle = math.radians(
                angle_degrees
            )

            inner = 9
            outer = 12

            x1 = int(
                center_x
                + math.cos(angle)
                * inner
            )

            y1 = int(
                center_y
                + math.sin(angle)
                * inner
            )

            x2 = int(
                center_x
                + math.cos(angle)
                * outer
            )

            y2 = int(
                center_y
                + math.sin(angle)
                * outer
            )

            draw.line(
                (x1, y1, x2, y2),
                fill=(255, 210, 50),
                width=1
            )

        return


    # =================================================
    # PARTLY CLOUDY
    # =================================================

    if code in (1, 2):

        # Small sun
        draw.ellipse(
            (
                20,
                6 + y_offset,
                31,
                17 + y_offset
            ),
            fill=(255, 210, 50)
        )

        # Cloud
        draw.ellipse(
            (
                22,
                12 + y_offset,
                36,
                24 + y_offset
            ),
            fill=(210, 210, 220)
        )

        draw.ellipse(
            (
                31,
                9 + y_offset,
                44,
                24 + y_offset
            ),
            fill=(210, 210, 220)
        )

        draw.rectangle(
            (
                22,
                17 + y_offset,
                44,
                24 + y_offset
            ),
            fill=(210, 210, 220)
        )

        return


    # =================================================
    # CLOUDY / FOG
    # =================================================

    if code in (
        3,
        45,
        48
    ):

        draw.ellipse(
            (
                17,
                11 + y_offset,
                34,
                25 + y_offset
            ),
            fill=(180, 180, 190)
        )

        draw.ellipse(
            (
                29,
                7 + y_offset,
                46,
                25 + y_offset
            ),
            fill=(180, 180, 190)
        )

        draw.rectangle(
            (
                17,
                18 + y_offset,
                46,
                25 + y_offset
            ),
            fill=(180, 180, 190)
        )

        # Fog lines
        if code in (45, 48):

            draw.line(
                (
                    18,
                    29 + y_offset,
                    45,
                    29 + y_offset
                ),
                fill=(130, 130, 140),
                width=1
            )

            draw.line(
                (
                    22,
                    33 + y_offset,
                    42,
                    33 + y_offset
                ),
                fill=(130, 130, 140),
                width=1
            )

        return


    # =================================================
    # RAIN
    # =================================================

    if (
        51 <= code <= 67
        or 80 <= code <= 82
    ):

        # Cloud
        draw.ellipse(
            (
                17,
                8 + y_offset,
                34,
                22 + y_offset
            ),
            fill=(175, 175, 185)
        )

        draw.ellipse(
            (
                29,
                6 + y_offset,
                46,
                22 + y_offset
            ),
            fill=(175, 175, 185)
        )

        draw.rectangle(
            (
                17,
                15 + y_offset,
                46,
                22 + y_offset
            ),
            fill=(175, 175, 185)
        )

        # Rain drops
        for x in (
            21,
            29,
            37,
            45
        ):

            draw.line(
                (
                    x,
                    26 + y_offset,
                    x - 2,
                    31 + y_offset
                ),
                fill=(70, 160, 255),
                width=2
            )

        return


    # =================================================
    # SNOW
    # =================================================

    if (
        71 <= code <= 77
        or 85 <= code <= 86
    ):

        # Cloud
        draw.ellipse(
            (
                17,
                8 + y_offset,
                34,
                22 + y_offset
            ),
            fill=(190, 190, 200)
        )

        draw.ellipse(
            (
                29,
                6 + y_offset,
                46,
                22 + y_offset
            ),
            fill=(190, 190, 200)
        )

        draw.rectangle(
            (
                17,
                15 + y_offset,
                46,
                22 + y_offset
            ),
            fill=(190, 190, 200)
        )

        # Snow dots
        for x, y in (
            (21, 27),
            (30, 30),
            (39, 27),
            (45, 32),
        ):

            y += y_offset

            draw.ellipse(
                (
                    x - 1,
                    y - 1,
                    x + 1,
                    y + 1
                ),
                fill=(255, 255, 255)
            )

        return


    # =================================================
    # THUNDERSTORM
    # =================================================

    if 95 <= code <= 99:

        # Cloud
        draw.ellipse(
            (
                17,
                8 + y_offset,
                34,
                22 + y_offset
            ),
            fill=(150, 150, 165)
        )

        draw.ellipse(
            (
                29,
                6 + y_offset,
                46,
                22 + y_offset
            ),
            fill=(150, 150, 165)
        )

        draw.rectangle(
            (
                17,
                15 + y_offset,
                46,
                22 + y_offset
            ),
            fill=(150, 150, 165)
        )

        # Lightning bolt
        draw.polygon(
            [
                (33, 23 + y_offset),
                (28, 32 + y_offset),
                (33, 31 + y_offset),
                (29, 40 + y_offset),
                (39, 28 + y_offset),
                (34, 29 + y_offset),
            ],
            fill=(255, 220, 40)
        )

        return


    # =================================================
    # UNKNOWN WEATHER
    # =================================================

    draw.ellipse(
        (
            18,
            9 + y_offset,
            45,
            26 + y_offset
        ),
        fill=(180, 180, 190)
    )

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

    # =================================================
    # Weather background thread
    # =================================================

    weather_state = WeatherState()
    weather_lock = threading.Lock()

    weather_thread = threading.Thread(
        target=poll_weather,
        args=(
            weather_state,
            weather_lock,
            stop_event,
            args.weather_latitude,
            args.weather_longitude,
            args.weather_update_seconds,
        ),
        daemon=True,
    )

    weather_thread.start()

    # =================================================
    # Display states
    # =================================================

    PLAYING = "PLAYING"
    PAUSED = "PAUSED"
    SHATTERING = "SHATTERING"
    SHATTER_HOLD = "SHATTER_HOLD"
    IDLE = "IDLE"

    display_state = IDLE

    # =================================================
    # Record rotation
    # =================================================

    angle = 0.0
    last_frame = time.monotonic()

    last_art_image = None
    rotation_frames = None

    NUM_ROTATION_FRAMES = 60

    # =================================================
    # Pause overlay
    # =================================================

    paused_image = None

    # =================================================
    # Shatter animation
    # =================================================

    SHATTER_FRAME_COUNT = 14

    # How long the actual breaking movement takes
    SHATTER_DURATION = args.shatter_duration

    # How long the broken CD stays afterward
    SHATTER_HOLD_SECONDS = args.shatter_hold

    shatter_frames = None
    shatter_start_time = None
    shatter_hold_start = None
    shatter_frame_index = 0

    # Tracks whether Spotify previously had a song.
    # This lets us detect the exact transition:
    #
    # SONG -> NO SONG
    #
    had_song = False

    # =================================================
    # Idle screens
    # =================================================

    clock_image = render_clock(size)
    last_clock_minute = None

    weather_image = render_weather(
        size,
        None,
        None,
        None,
        None,
        True
    )

    last_weather_render_key = None

    # How long each idle screen remains
    # fully visible.
    IDLE_SCREEN_DURATION = (
        args.idle_screen_duration
    )

    idle_screens = [
        "BIRTHDAY",
        "IMAGE1",
        "IMAGE2",
        "IMAGE3",
        "CLOCK",
        "WEATHER",
    ]

    idle_screen_index = 0

    current_idle_screen = (
        idle_screens[idle_screen_index]
    )

    previous_idle_screen = (
        current_idle_screen
    )

    idle_screen_start_time = (
        time.monotonic()
    )

    # =================================================
    # Fade transitions
    # =================================================

    FADE_DURATION = args.fade_duration

    previous_display_state = display_state

    fade_active = False
    fade_start_time = None

    fade_from_image = None
    fade_to_image = None
    last_displayed_image = None

    # =================================================
    # Images render
    # =================================================

    image1 = render_picture(
        "images/aidenalaina.png",
        size
    )

    image2 = render_picture(
        "images/freddy.png",
        size
    )

    image3 = render_picture(
        "images/aidenalaina2.png",
        size
    )

    # =================================================
    # Performance counters
    # =================================================

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

            # =================================================
            # Get current weather state
            # =================================================

            with weather_lock:

                current_temperature = (
                    weather_state.temperature
                )

                current_weather_code = (
                    weather_state.weather_code
                )

                current_weather_high = (
                    weather_state.high
                )

                current_weather_low = (
                    weather_state.low
                )

                current_weather_is_day = (
                    weather_state.is_day
                )

            lock_time = (
                    time.monotonic()
                    - lock_start
            )

            total_lock_time += lock_time

            has_song = (
                    current_art_image is not None
            )

            # =================================================
            # New song / new album artwork
            # =================================================

            if (
                    current_art_image is not None
                    and current_art_image is not last_art_image
            ):
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

                prepare_elapsed = (
                        time.monotonic()
                        - prepare_start
                )

                print(
                    f"Rotation frames ready in "
                    f"{prepare_elapsed:.2f} seconds"
                )

                last_art_image = current_art_image

                # New artwork means any old pause
                # image is invalid.
                paused_image = None

                # Cancel an old shatter if Spotify
                # starts playing something new.
                shatter_frames = None
                shatter_start_time = None
                shatter_hold_start = None

                # New CD starts upright.
                angle = 0.0

            # =================================================
            # Determine display state
            # =================================================

            if has_song:

                had_song = True

                if is_playing:

                    display_state = PLAYING
                    paused_image = None

                else:

                    display_state = PAUSED


            else:

                # ---------------------------------------------
                # Spotify JUST went from a song to no song
                # ---------------------------------------------

                if (
                        had_song
                        and rotation_frames is not None
                ):

                    print(
                        "Spotify stopped - "
                        "preparing shatter animation..."
                    )

                    # Find the exact record orientation that
                    # was visible when playback disappeared.
                    frame_index = int(
                        (angle / 360.0)
                        * len(rotation_frames)
                    ) % len(rotation_frames)

                    current_cd = (
                        rotation_frames[
                            frame_index
                        ]
                    )

                    prepare_start = (
                        time.monotonic()
                    )

                    shatter_frames = (
                        prepare_shatter_frames(
                            current_cd,
                            SHATTER_FRAME_COUNT
                        )
                    )

                    print(
                        f"Shatter frames ready in "
                        f"{time.monotonic() - prepare_start:.2f} "
                        f"seconds"
                    )

                    shatter_start_time = (
                        time.monotonic()
                    )

                    shatter_hold_start = None
                    shatter_frame_index = 0

                    display_state = SHATTERING

                    # Prevent this block from firing
                    # repeatedly every loop.
                    had_song = False

                    paused_image = None


                # ---------------------------------------------
                # No song and we're not currently doing
                # the shatter sequence
                # ---------------------------------------------

                elif display_state not in (
                        SHATTERING,
                        SHATTER_HOLD
                ):

                    display_state = IDLE


            # =================================================
            # Time / rotation calculation
            # =================================================

            now = time.monotonic()

            delta = (
                    now
                    - last_frame
            )

            last_frame = now

            if (
                    display_state == PLAYING
                    and rotation_frames is not None
            ):
                angle = (
                                angle
                                - 360.0
                                * (args.rpm / 60.0)
                                * delta
                        ) % 360.0

            # =================================================
            # Advance shatter animation
            # =================================================

            if (
                    display_state == SHATTERING
                    and shatter_frames is not None
                    and shatter_start_time is not None
            ):

                shatter_elapsed = (
                        now
                        - shatter_start_time
                )

                shatter_progress = min(
                    1.0,
                    shatter_elapsed
                    / SHATTER_DURATION
                )

                shatter_frame_index = min(
                    int(
                        shatter_progress
                        * len(shatter_frames)
                    ),
                    len(shatter_frames) - 1
                )

                # Animation has reached the final
                # shattered position.
                if shatter_progress >= 1.0:
                    display_state = SHATTER_HOLD

                    shatter_hold_start = now

            # =================================================
            # Hold broken CD for 5 seconds
            # =================================================

            if (
                    display_state == SHATTER_HOLD
                    and shatter_hold_start is not None
            ):

                if (
                        now
                        - shatter_hold_start
                        >= SHATTER_HOLD_SECONDS
                ):
                    display_state = IDLE

                    # Always restart idle mode from clock.
                    idle_screen_index = 0

                    current_idle_screen = (
                        idle_screens[0]
                    )

                    previous_idle_screen = (
                        current_idle_screen
                    )

                    idle_screen_start_time = now

                    shatter_frames = None
                    shatter_start_time = None
                    shatter_hold_start = None

                    # We're finished with the old album.
                    rotation_frames = None
                    last_art_image = None
                    paused_image = None

            # =================================================
            # Rotate idle screens
            # =================================================

            if display_state == IDLE:

                idle_elapsed = (
                        now
                        - idle_screen_start_time
                )

                if (
                        idle_elapsed >= IDLE_SCREEN_DURATION
                        and not fade_active
                ):
                    idle_screen_index = (
                                                idle_screen_index + 1
                                        ) % len(idle_screens)

                    current_idle_screen = (
                        idle_screens[
                            idle_screen_index
                        ]
                    )

                    print(
                        f"Idle screen changed to: "
                        f"{current_idle_screen}",
                        flush=True
                    )

                    idle_screen_start_time = (
                            now + FADE_DURATION
                    )

            # =================================================
            # Select image to display
            # =================================================

            render_start = time.monotonic()

            # -------------------------------------------------
            # PLAYING
            # -------------------------------------------------

            if (
                    display_state == PLAYING
                    and rotation_frames is not None
            ):

                frame_index = int(
                    (angle / 360.0)
                    * len(rotation_frames)
                ) % len(rotation_frames)

                image = (
                    rotation_frames[
                        frame_index
                    ]
                )


            # -------------------------------------------------
            # PAUSED
            # -------------------------------------------------

            elif (
                    display_state == PAUSED
                    and rotation_frames is not None
            ):

                frame_index = int(
                    (angle / 360.0)
                    * len(rotation_frames)
                ) % len(rotation_frames)

                # Only generate this once when
                # playback becomes paused.
                if paused_image is None:
                    paused_image = (
                        add_pause_overlay(
                            rotation_frames[
                                frame_index
                            ]
                        )
                    )

                image = paused_image


            # -------------------------------------------------
            # SHATTERING
            # -------------------------------------------------

            elif (
                    display_state == SHATTERING
                    and shatter_frames is not None
            ):

                image = (
                    shatter_frames[
                        shatter_frame_index
                    ]
                )


            # -------------------------------------------------
            # SHATTERED CD HOLD
            # -------------------------------------------------

            elif (
                    display_state == SHATTER_HOLD
                    and shatter_frames is not None
            ):

                image = (
                    shatter_frames[-1]
                )


            # -------------------------------------------------
            # IDLE SCREENS
            # -------------------------------------------------

            else:

                # =============================================
                # CLOCK
                # =============================================

                if current_idle_screen == "CLOCK":

                    current_minute = (
                        time.strftime(
                            "%Y%m%d%H%M"
                        )
                    )

                    # No need to redraw the clock
                    # every frame.
                    if (
                            current_minute
                            != last_clock_minute
                    ):
                        clock_image = (
                            render_clock(size)
                        )

                        last_clock_minute = (
                            current_minute
                        )

                    image = clock_image


                # =============================================
                # WEATHER
                # =============================================

                elif current_idle_screen == "WEATHER":

                    current_weather_date = time.strftime(
                        "%Y%m%d"
                    )

                    weather_render_key = (
                        current_temperature,
                        current_weather_code,
                        current_weather_high,
                        current_weather_low,
                        current_weather_is_day,
                        current_weather_date,
                    )

                    # Only redraw if weather changed.
                    if (
                            weather_render_key
                            != last_weather_render_key
                    ):
                        weather_image = render_weather(
                            size,
                            current_temperature,
                            current_weather_code,
                            current_weather_high,
                            current_weather_low,
                            current_weather_is_day,
                        )

                        last_weather_render_key = (
                            weather_render_key
                        )

                    image = weather_image

                # =============================================
                # BIRTHDAY
                # =============================================

                elif current_idle_screen == "BIRTHDAY":

                    image = render_birthday(
                        size
                    )

                # =============================================
                # IMAGES
                # =============================================

                elif current_idle_screen == "IMAGE1":

                    image = image1

                elif current_idle_screen == "IMAGE2":

                    image = image2

                elif current_idle_screen == "IMAGE3":

                    image = image3

            # =================================================
            # Start fade when display state changes
            # =================================================

            fade_transitions = {
                (IDLE, PLAYING),
                (IDLE, PAUSED),

                (SHATTER_HOLD, IDLE),
            }

            if display_state != previous_display_state:

                if (
                        previous_display_state,
                        display_state
                ) in fade_transitions:

                    if last_displayed_image is not None:
                        fade_from_image = (
                            last_displayed_image.copy()
                        )
                    else:
                        fade_from_image = image.copy()

                    fade_to_image = image.copy()

                    fade_start_time = time.monotonic()
                    fade_active = True

                previous_display_state = display_state

            # =================================================
            # Fade between idle screens
            # =================================================

            idle_screen_changed = (
                    display_state == IDLE
                    and current_idle_screen
                    != previous_idle_screen
            )

            if idle_screen_changed:

                if last_displayed_image is not None:

                    fade_from_image = (
                        last_displayed_image.copy()
                    )

                else:

                    fade_from_image = (
                        image.copy()
                    )

                fade_to_image = (
                    image.copy()
                )

                fade_start_time = (
                    time.monotonic()
                )

                fade_active = True

                previous_idle_screen = (
                    current_idle_screen
                )

            # =================================================
            # Apply fade-out / fade-in
            # =================================================

            if (
                    fade_active
                    and fade_start_time is not None
                    and fade_from_image is not None
                    and fade_to_image is not None
            ):

                fade_elapsed = (
                        time.monotonic()
                        - fade_start_time
                )

                fade_progress = min(
                    1.0,
                    fade_elapsed / FADE_DURATION
                )

                # First half:
                # old image fades to black
                if fade_progress < 0.5:

                    dark_amount = (
                            fade_progress / 0.5
                    )

                    image = blend_with_black(
                        fade_from_image,
                        dark_amount
                    )

                # Second half:
                # new image fades in from black
                else:

                    dark_amount = (
                            1.0
                            - (
                                    (fade_progress - 0.5)
                                    / 0.5
                            )
                    )

                    image = blend_with_black(
                        fade_to_image,
                        dark_amount
                    )

                if fade_progress >= 1.0:
                    fade_active = False
                    image = fade_to_image
            # =================================================
            # Finish render timing
            # =================================================

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

            last_displayed_image = image.copy()

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
                    f"State: {display_state} | "
                    f"FPS: {actual_fps:.1f} | "
                    f"Lock: {avg_lock_ms:.1f} ms | "
                    f"Render: {avg_render_ms:.1f} ms | "
                    f"Display: {avg_display_ms:.1f} ms | "
                    f"Measured: {total_measured_ms:.1f} ms"
                )

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

        weather_thread.join(timeout=1)

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
    parser.add_argument("--poll-seconds", type=positive_float, default=1)
    parser.add_argument("--fps", type=positive_float, default=20.0)
    parser.add_argument("--rpm", type=positive_float, default=10.0)
    parser.add_argument("--fade-duration",type=positive_float,default=0.6,help="Total fade-out/fade-in transition time in seconds.")
    parser.add_argument("--shatter-duration",type=positive_float,default=0.7,help="Length of the CD shatter animation in seconds.")
    parser.add_argument("--shatter-hold",type=positive_float,default=5.0,help="How long the shattered CD remains on screen in seconds.")
    parser.add_argument("--token-cache", type=Path, default=Path(".cache/spotify_token.json"))
    parser.add_argument("--mock-output", type=Path, help="Write the current frame PNG instead of using RGB matrix hardware.")
    parser.add_argument("--preview-frames", type=Path, help="Render sample spinning-album-art disk frames and exit.")
    parser.add_argument("--auth-only", action="store_true", help="Authorize Spotify, cache the token, and exit without using the matrix.")
    parser.add_argument("--test-pattern", action="store_true", help="Show a bright moving color test pattern without using Spotify.")
    parser.add_argument("--once", action="store_true", help="Render one frame and exit.")
    parser.add_argument("--no-browser", action="store_true", help="Print the Spotify auth URL without trying to open a browser.")
    parser.add_argument("--idle-screen-duration",type=positive_float,default=15.0,help="Seconds each idle screen stays visible.")
    parser.add_argument("--weather-update-seconds",type=positive_float,default=900.0,help="Seconds between weather updates.")
    parser.add_argument("--weather-latitude",type=float,default=29.6516,help="Latitude used for weather.")
    parser.add_argument("--weather-longitude",type=float,default=-82.3248,help="Longitude used for weather.")
    return parser


if __name__ == "__main__":
    run(build_parser().parse_args())
