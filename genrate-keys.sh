#!/bin/sh

KEY_DIR="test-keys"

println() {
	echo -e "$1\n"
}

confirm_overwrite() {
	file="$1"

	if [ ! -f "$KEY_DIR/$file" ]; then
		return 0
	fi

	printf "%s already exists. Overwrite? (y/N) " "$file"
	read -r choice || choice=

	case "$choice" in
	y | Y) return 0 ;;
	*) println "Skipping $file genration" && return 1 ;;
	esac
}

generate_key_pair() {
	algorithm="$1"
	private_key_file="$2"
	public_key_file="$3"
	shift 3

	if ! confirm_overwrite "$private_key_file"; then
		return 0
	fi

	if ! openssl genpkey -algorithm "$algorithm" "$@" \
		-out "$KEY_DIR/$private_key_file" >/dev/null 2>&1; then
		println "Failed to generate $private_key_file"
		return 1
	fi

	println "Successfully generated $private_key_file"

	if ! confirm_overwrite "$public_key_file"; then
		return 0
	fi

	if openssl pkey -in "$KEY_DIR/$private_key_file" -pubout \
		-out "$KEY_DIR/$public_key_file" >/dev/null 2>&1; then
		println "Successfully generated $public_key_file"
	else
		println "Failed to generate $public_key_file"
		return 1
	fi
}

echo

generate_key_pair RSA \
	"rsa_private_key.pem" \
	"rsa_public_key.pem" \
	-pkeyopt "rsa_keygen_bits:2048" || :

generate_key_pair ed25519 \
	"ed25519_private_key.pem" \
	"ed25519_public_key.pem" || :
