# The official dxflrs/garage image is scratch-based and ships *only* the
# `/garage` binary -- no shell, so it can't self-bootstrap (cluster layout,
# access key import, bucket creation) the way minio-init used to for MinIO.
# This repackages that same binary (verified: dxflrs/garage:v1.0.1) in a
# minimal Alpine image so entrypoint.sh can do first-boot setup and then run
# the server in the foreground.
FROM dxflrs/garage:v1.0.1 AS garage-bin

FROM alpine:3.19
RUN apk add --no-cache curl
COPY --from=garage-bin /garage /usr/local/bin/garage
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
