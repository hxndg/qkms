package qkms_common

const QKMS_ERROR_CODE_READ_AK_SUCCESS = 200
const QKMS_ERROR_CODE_READ_AK_NOT_EXIST = 201
const QKMS_ERROR_CODE_READ_AK_NOT_AUTHORIZED = 201

const QKMS_ERROR_CODE_CREATE_AK_SUCCESS = 202
const QKMS_ERROR_CODE_CREATE_AK_FAILED = 203
const QKMS_ERROR_CODE_CREATE_AK_ALREADY_EXIST = 203
const QKMS_ERROR_CODE_CREATE_AK_NO_KEK = 204

const QKMS_ERROR_CODE_UPDATE_AK_INFO_MISMATCH = 204
const QKMS_ERROR_CODE_UPDATE_AK_NOT_AUTHORIZED = 205
const QKMS_ERROR_CODE_UPDATE_AK_FAILED = 209
const QKMS_ERROR_CODE_UPDATE_AK_SUCCESS = 205

const QKMS_ERROR_CODE_INTERNAL_KEK_NOT_FOUND = 404
const QKMS_ERROR_CODE_INTERNAL_KEK_VERSION_MISMATCH = 407
const QKMS_ERROR_CODE_INTERNAL_KEK_FOUND = 408

const QKMS_ERROR_CODE_INTERNAL_ERROR = 500
const QKMS_ERROR_CODE_CREATE_KEK_FAILED = 500
const QKMS_ERROR_CODE_CREATE_KEK_SUCCESS = 501

const QKMS_ERROR_CODE_INVALID_OPERATION = 505
const QKMS_ERROR_CODE_READ_INVALID = 506
const QKMS_ERROR_CODE_OPERATION_VALIDATION_UNKNOWN = 509
const QKMS_ERROR_CODE_WRITE_INVALID = 506
const QKMS_ERROR_CODE_READ_VALID = 506
const QKMS_ERROR_CODE_WRITE_VALID = 506

const QKMS_ERROR_CODE_CREATE_KAR_SUCCESS = 509
const QKMS_ERROR_CODE_CREATE_KAR_FAILED = 510

const QKMS_ERROR_CODE_KAR_FIND = 511
const QKMS_ERROR_CODE_KAR_NOT_FIND = 512

const QKMS_ERROR_CODE_CACHE_KAR_UPDATE = 513

const QKMS_ERROR_CODE_KAR_GRANTED = 515
