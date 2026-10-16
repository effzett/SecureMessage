#!/usr/bin/env bash
# Packt dist/SecureMessage.app zusammen mit der LIESMICH in ein DMG.
# Aufruf: packaging/build_dmg.sh <Ausgabe.dmg>
set -euo pipefail

APP_NAME="SecureMessage"
APP_PATH="dist/${APP_NAME}.app"
DMG_PATH="$1"

if [[ ! -d "${APP_PATH}" ]]; then
  echo "FEHLER: ${APP_PATH} wurde nicht erzeugt." >&2
  exit 1
fi

# Ad-hoc-Signatur über das ganze Bundle, damit Apple Silicon die App startet.
codesign --force --deep --sign - "${APP_PATH}"
codesign --verify --deep --strict "${APP_PATH}"

# Staging außerhalb des Workspace, damit Spotlight/mdworker den Ordner nicht
# indexiert und hdiutil nicht mit "Resource busy" abbricht.
STAGE="$(mktemp -d "${TMPDIR:-/tmp}/sm_dmg_stage.XXXXXX")"
trap 'rm -rf "${STAGE}"' EXIT
cp -R "${APP_PATH}" "${STAGE}/"
cp packaging/LIESMICH-macOS.txt "${STAGE}/LIESMICH.txt"
ln -s /Applications "${STAGE}/Programme"
mdutil -i off "${STAGE}" >/dev/null 2>&1 || true
touch "${STAGE}/.metadata_never_index"
sync

rm -f "${DMG_PATH}"
for attempt in 1 2 3 4 5; do
  if hdiutil create -volname "${APP_NAME}" -srcfolder "${STAGE}" \
      -fs HFS+ -ov -format UDZO "${DMG_PATH}"; then
    echo "==> Fertig: ${DMG_PATH}"
    exit 0
  fi
  echo "   hdiutil-Versuch ${attempt} fehlgeschlagen, neuer Versuch in 5 s …" >&2
  sleep 5
done
echo "FEHLER: DMG konnte nach mehreren Versuchen nicht erzeugt werden." >&2
exit 1
