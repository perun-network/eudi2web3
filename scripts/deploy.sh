set -e

# --delete to avoid outdated files (e.g. after a rename).
#   it will not delete excluded files, which is what we want.
# .a files in zkey/lib are not portable.
# -a includes -t and thus preserves mtime => make should run as expected and not regenerate the key material.
rsync -av --delete \
    --exclude .git \
    --exclude ptau \
    --exclude zkey/lib \
    --exclude 'zkey/**/*.sym' \
    --exclude circuits \
    --exclude target \
    . erdstall:/mnt/eudi2web3/
#    . erdstall:/var/www/eudi2web3/

exit 0

ssh erdstall '
    set -e
    # cd /var/www/eudi2web3
    cd /mnt/eudi2web3
    make zkey/lib/{libbls12-381_minimal.a,libbls12-381_small.a,libbn254_minimal.a,libbn254_sdjwt_es256_sha256_1claim.a,libbn254_small_nocrypto.a}
    cargo build --release
    # sudo systemctl restart eudi2web3
    '
