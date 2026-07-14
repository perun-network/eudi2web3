set -e

TAG=$(git describe --always --dirty --abbrev=7)

# Update contract json files (are published via rsync and are not in the docker image).
make zkey/bls12-381/{small,tiny}{,_nocrypto}.cardano.json

# Build docker image
docker build -t "eudi2web3:$TAG" .

# Update the image on the server-side if it changed
LOCAL=$(docker image inspect "eudi2web3:$TAG" --format '{{.Id}}')
REMOTE=$(ssh zombienet "docker image inspect eudi2web3:$TAG --format '{{.Id}}' 2>/dev/null || true")
if [ "$LOCAL" != "$REMOTE" ]; then
    docker save "eudi2web3:$TAG" | gzip | ssh zombienet 'gunzip | docker load'
fi

# Transfer all other files needed to run the server
rsync -av \
    --include 'fubar_*.pem' \
    --include 'me.addr' \
    --include 'me.sk' \
    --include 'zkey/' \
    --include 'zkey/bls12-381/' \
    --include 'zkey/bls12-381/*.0001.zkey' \
    --include 'zkey/bls12-381/*.cardano.json' \
    --include 'zkey/bn254/' \
    --include 'zkey/bn254/small*.0001.zkey' \
    --exclude='*' \
    . zombienet:/home/zombienetadmin/eudi/

# Recreate the container
ssh zombienet TAG="$TAG" '
    docker stop eudi2web3 || true
    docker rm eudi2web3 || true
    docker run --init -d \
        --name eudi2web3 \
        --restart unless-stopped \
        -p 8080:8080 \
        --env-file $PWD/eudi/.env \
        -v "$PWD/eudi/zkey:/zkey:ro" \
        -v "$PWD/eudi/fubar_cert.pem:/fubar_cert.pem:ro" \
        -v "$PWD/eudi/fubar_privkey.pem:/fubar_privkey.pem:ro" \
        -v "$PWD/eudi/me.addr:/me.addr:ro" \
        -v "$PWD/eudi/me.sk:/me.sk:ro" \
     	"eudi2web3:$TAG"
'

