"""Sender and recipient address extraction components."""

from src.analyzers.sender.contracts import (
    AddressParser,
    HeaderProvider,
    SenderExtractor,
)
from src.analyzers.sender.extractor import RfcAddressParser, StructuredSenderExtractor
from src.analyzers.sender.header_sources import (
    MappingHeaderProvider,
    MessageHeaderProvider,
)

__all__ = [
    "AddressParser",
    "HeaderProvider",
    "MappingHeaderProvider",
    "MessageHeaderProvider",
    "RfcAddressParser",
    "SenderExtractor",
    "StructuredSenderExtractor",
]
