from enum import Enum


class Capability(str, Enum):
    IN_SCOPE = "in_scope"
    OUT_OF_SCOPE_FIRMWARE = "out_of_scope_firmware"
    OUT_OF_SCOPE_HARDWARE = "out_of_scope_hardware"
    OUT_OF_SCOPE_CRYPTO = "out_of_scope_crypto"
    OUT_OF_SCOPE_OTHER = "out_of_scope_other"
