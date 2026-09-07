import unittest
from io import BytesIO

from PIL import Image

from media_authenticity import (
    _extract_json,
    _normalize_result,
    _validate_public_url,
    inspect_image_metadata,
    validate_image_bytes,
)


class MediaAuthenticityTests(unittest.TestCase):
    def test_extracts_fenced_json(self):
        result = _extract_json('```json\n{"probability_ai": 80}\n```')
        self.assertEqual(result["probability_ai"], 80)

    def test_normalizes_probability_and_label(self):
        result = _normalize_result({"probability_ai": 91, "evidence": ["sinal"]})
        self.assertEqual(result["classification"], "alta_probabilidade_ia")
        self.assertEqual(result["probability_ai"], 91)

    def test_reads_image_dimensions(self):
        buffer = BytesIO()
        Image.new("RGB", (12, 8), "white").save(buffer, format="PNG")
        data = buffer.getvalue()
        validate_image_bytes(data)
        metadata = inspect_image_metadata(data)
        self.assertEqual((metadata["width"], metadata["height"]), (12, 8))

    def test_rejects_invalid_image(self):
        with self.assertRaisesRegex(ValueError, "imagem válida"):
            validate_image_bytes(b"not-an-image")

    def test_rejects_non_http_url(self):
        with self.assertRaisesRegex(ValueError, "HTTP ou HTTPS"):
            _validate_public_url("file:///etc/passwd")


if __name__ == "__main__":
    unittest.main()
