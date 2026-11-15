#!/bin/sh
# publish-r2.sh OUT: uploads a generated database (python3 -m vulndb.gen OUT)
# to the R2 bucket behind vuln.xolang.org (decision 0647 of xo-lang/xo),
# through R2's S3 API with the aws CLI. It adds and replaces files and never
# deletes. Order: every ID/ entry, then index/vulns.json, index/modules.json,
# vulndb.zip, index.txt and last index/db.json, so a client that sees a new
# db.json finds every entry the indexes name.
#
# Environment: R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY (a token scoped to the
# bucket only), R2_ENDPOINT (https://<account id>.r2.cloudflarestorage.com,
# a secret), R2_BUCKET (default xo-vulndb), DRY_RUN=1 (print each upload).
set -eu
out=${1:?usage: publish-r2.sh OUT}
[ -f "$out/index/db.json" ] || { echo "publish-r2: $out/index/db.json is missing; not a generated database" >&2; exit 2; }
bucket=${R2_BUCKET:-xo-vulndb}
if [ "${DRY_RUN:-0}" != 1 ]; then
  : "${R2_ACCESS_KEY_ID:?publish-r2: R2_ACCESS_KEY_ID is not set}"
  : "${R2_SECRET_ACCESS_KEY:?publish-r2: R2_SECRET_ACCESS_KEY is not set}"
  : "${R2_ENDPOINT:?publish-r2: R2_ENDPOINT is not set}"
  case $R2_ENDPOINT in
    https://*.r2.cloudflarestorage.com) ;;
    *) echo "publish-r2: R2_ENDPOINT must be https://<account id>.r2.cloudflarestorage.com" >&2; exit 2 ;;
  esac
  export AWS_ACCESS_KEY_ID="$R2_ACCESS_KEY_ID" AWS_SECRET_ACCESS_KEY="$R2_SECRET_ACCESS_KEY"
  export AWS_DEFAULT_REGION=auto AWS_EC2_METADATA_DISABLED=true
  export AWS_REQUEST_CHECKSUM_CALCULATION=when_required AWS_RESPONSE_CHECKSUM_VALIDATION=when_required
  unset AWS_PROFILE AWS_SESSION_TOKEN
fi
ctype() {
  case $1 in
    *.json) echo "application/json" ;;
    *.txt) echo "text/plain; charset=utf-8" ;;
    *.zip) echo "application/zip" ;;
    *) echo "application/octet-stream" ;;
  esac
}
cache() {
  case $1 in
    ID/*) echo "public, max-age=3600" ;;
    *) echo "public, max-age=300" ;;
  esac
}
put() {
  if [ "${DRY_RUN:-0}" = 1 ]; then
    printf 'put %s\t%s\t%s\n' "$1" "$(ctype "$1")" "$(cache "$1")"
  else
    aws s3api put-object --endpoint-url "$R2_ENDPOINT" --bucket "$bucket" --key "$1" \
      --body "$out/$1" --content-type "$(ctype "$1")" --cache-control "$(cache "$1")" > /dev/null
  fi
}
for f in $(cd "$out" && find ID -type f -name 'XO-*.json' | LC_ALL=C sort); do
  case $f in ID/XO-[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9].json) ;; *) echo "publish-r2: refusing $f" >&2; exit 2 ;; esac
  put "$f"
done
for f in index/vulns.json index/modules.json vulndb.zip index.txt index/db.json; do put "$f"; done
echo "publish-r2: done ($bucket)"
