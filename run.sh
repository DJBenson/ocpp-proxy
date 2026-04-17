#!/usr/bin/with-contenv bashio

# Read configuration from /data/options.json via bashio helpers
MODE=$(bashio::config 'mode')
UPSTREAM=$(bashio::config 'upstream')
VERBOSE=$(bashio::config 'verbose')

# Build args as an array so values with spaces are handled correctly
ARGS=("--upstream" "${UPSTREAM}")
if [ "${VERBOSE}" = "true" ]; then
    ARGS+=("--verbose")
fi

if [ "${MODE}" = "proxy" ] || [ "${MODE}" = "masquerade" ]; then
    HOST=$(bashio::config 'host')
    PORT=$(bashio::config 'port')
    TLS=$(bashio::config 'tls')

    ARGS+=("${MODE}" "--host" "${HOST}" "--port" "${PORT}")

    if [ "${TLS}" = "true" ]; then
        CERT=$(bashio::config 'cert')
        KEY=$(bashio::config 'key')
        if [ -z "${CERT}" ] || [ -z "${KEY}" ]; then
            bashio::log.fatal "TLS is enabled but 'cert' and/or 'key' are not set."
            exit 1
        fi
        ARGS+=("--tls" "--cert" "${CERT}" "--key" "${KEY}")
    fi

    UPSTREAM_PASSWORD=$(bashio::config 'upstream_password')
    if [ -n "${UPSTREAM_PASSWORD}" ]; then ARGS+=("--upstream-password" "${UPSTREAM_PASSWORD}"); fi

    UPSTREAM_CPID=$(bashio::config 'upstream_charge_point_id')
    if [ -n "${UPSTREAM_CPID}" ]; then ARGS+=("--upstream-charge-point-id" "${UPSTREAM_CPID}"); fi

    if [ "${MODE}" = "masquerade" ]; then
        MASQ_VENDOR=$(bashio::config 'masquerade_vendor')
        MASQ_MODEL=$(bashio::config 'masquerade_model')
        MASQ_FIRMWARE=$(bashio::config 'masquerade_firmware')
        MASQ_SERIAL=$(bashio::config 'masquerade_serial')
        if [ -n "${MASQ_VENDOR}" ];   then ARGS+=("--vendor"   "${MASQ_VENDOR}");   fi
        if [ -n "${MASQ_MODEL}" ];    then ARGS+=("--model"    "${MASQ_MODEL}");    fi
        if [ -n "${MASQ_FIRMWARE}" ]; then ARGS+=("--firmware" "${MASQ_FIRMWARE}"); fi
        if [ -n "${MASQ_SERIAL}" ];   then ARGS+=("--serial"   "${MASQ_SERIAL}");   fi
        bashio::log.info "Starting OCPP masquerade proxy on ${HOST}:${PORT} -> ${UPSTREAM}"
    else
        bashio::log.info "Starting OCPP proxy on ${HOST}:${PORT} -> ${UPSTREAM}"
    fi

elif [ "${MODE}" = "simulate" ]; then
    CHARGE_POINT_ID=$(bashio::config 'charge_point_id')
    VENDOR=$(bashio::config 'vendor')
    MODEL=$(bashio::config 'model')
    FIRMWARE=$(bashio::config 'firmware')
    SERIAL=$(bashio::config 'serial')

    if [ -z "${CHARGE_POINT_ID}" ]; then
        bashio::log.fatal "simulate mode requires 'charge_point_id' to be set."
        exit 1
    fi

    ARGS+=("simulate" "--charge-point-id" "${CHARGE_POINT_ID}" "--vendor" "${VENDOR}" "--model" "${MODEL}" "--firmware" "${FIRMWARE}")

    if [ -n "${SERIAL}" ]; then
        ARGS+=("--serial" "${SERIAL}")
    fi

    bashio::log.info "Starting OCPP simulator as charge point ${CHARGE_POINT_ID} -> ${UPSTREAM}"

else
    bashio::log.fatal "Unknown mode '${MODE}'. Must be 'proxy', 'masquerade', or 'simulate'."
    exit 1
fi

exec python3 /app/ocpp-proxy.py "${ARGS[@]}"
