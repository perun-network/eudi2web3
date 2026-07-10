set -e

# Build docker image
docker build -t eudi2web3:dev .

# Update the image on the server-side if it changed
LOCAL=$(docker image inspect eudi2web3:dev --format '{{.Id}}')
REMOTE=$(ssh zombienet 'docker image inspect eudi2web3:dev --format "{{.Id}}" 2>/dev/null || true')
if [ "$LOCAL" != "$REMOTE" ]; then
    docker save eudi2web3:dev | gzip | ssh zombienet 'gunzip | docker load'
fi

# Transfer all other files needed to run the server
rsync -av \
    --include 'fubar_*.pem' \
    --include 'zkey/' \
    --include 'zkey/bls12-381/' \
    --include 'zkey/bls12-381/*.0001.zkey' \
    --include 'zkey/bn254/' \
    --include 'zkey/bn254/small*.0001.zkey' \
    --exclude='*' \
    . zombienet:/home/zombienetadmin/eudi/

