from app.config import PARSER_VERSION
from app.parser.eml_parser import parse_email
from app.parser.models import AttachmentMetadata, HeaderAddress, ParsedEmail

__all__ = ["parse_email", "PARSER_VERSION", "ParsedEmail", "HeaderAddress", "AttachmentMetadata"]
