# TOMBSTONE: build/publish now lives in .github/workflows/shared-layer-build.yml (ENC-TSK-P13).
#
# This comment previously pointed at ".github/workflows/_deploy.yml matrix build" --
# that pointer was FALSE for as long as it existed. _build.yml's function-discovery
# glob (`find backend/lambda -maxdepth 2 -name lambda_function.py`) structurally never
# matches shared_layer/ (a Lambda LAYER has no lambda_function.py), and `git grep` for
# publish-layer-version / PublishLayerVersion across .github/workflows/ returned zero
# hits anywhere -- confirmed during ENC-TSK-P13. No workflow built or published this
# layer at all from the moment this file was first tombstoned until shared-layer-build.yml
# landed. The two most recent published versions (:11, :12) were both hand-run via the
# AWS CLI by a human operator, not CI -- see backend/lambda/shared_layer/PROVENANCE.json
# for the full forensic record (CloudTrail-confirmed actor, source IP, and commit
# correlation) and this file's own git history (commit b826fd3 already tried to restore
# this script once, for exactly this reason, before being re-tombstoned without a
# replacement landing).
