.PHONY: build build-geth build-solc build-viem submodules install-deps \
       clean clean-geth clean-solc clean-viem \
       contracts test devnet devnet-stop \
       e2e e2e-simple e2e-kernel e2e-kernel-validator e2e-hooked \
       e2e-coinbase-ecdsa e2e-coinbase-webauthn e2e-light-account \
       e2e-negative-mempool e2e-negative-protocol e2e-negative \
       e2e-mldsa e2e-eoa e2e-eoa-batching e2e-eoa-sponsor e2e-eoa-p256 \
       benchmark

BUILD_DIR := $(CURDIR)/build
GETH_BIN := $(BUILD_DIR)/bin/geth
SOLC_BIN := $(BUILD_DIR)/bin/solc

build: submodules install-deps build-geth build-solc build-viem
	@echo "Build complete."
	@echo "  geth: $(GETH_BIN)"
	@echo "  solc: $(SOLC_BIN)"
	@echo "  viem: viem-eip8141/src (_esm, _cjs, _types)"

submodules:
	git submodule update --init --recursive

install-deps:
	cd viem-eip8141 && pnpm install --frozen-lockfile
	cd contracts && npm ci

build-geth:
	$(MAKE) -C 8141-geth geth
	@mkdir -p $(BUILD_DIR)/bin
	cp 8141-geth/build/bin/geth $(GETH_BIN)

build-solc:
	@mkdir -p $(BUILD_DIR)/solc
	cd $(BUILD_DIR)/solc && cmake $(CURDIR)/solidity-eip8141 -DCMAKE_BUILD_TYPE=Release
	$(MAKE) -C $(BUILD_DIR)/solc solc
	@mkdir -p $(BUILD_DIR)/bin
	cp $(BUILD_DIR)/solc/solc/solc $(SOLC_BIN)

build-viem:
	cd viem-eip8141 && pnpm build

contracts:
	cd contracts && forge build

test:
	cd contracts && forge test -vv

devnet:
	bash devnet/run.sh

devnet-stop:
	@pkill -f 'geth.*--dev' 2>/dev/null && echo "devnet stopped" || echo "devnet not running"

# E2E tests (require devnet running)
e2e-simple:
	cd contracts && npx tsx e2e/simple/simple-basic.ts

e2e-kernel:
	cd contracts && npx tsx e2e/kernel/kernel-basic.ts

e2e-kernel-validator:
	cd contracts && npx tsx e2e/kernel/kernel-validator.ts

e2e-hooked:
	cd contracts && npx tsx e2e/kernel-hooked/spending-limit.ts

e2e-coinbase-ecdsa:
	cd contracts && npx tsx e2e/coinbase/coinbase-ecdsa.ts

e2e-coinbase-webauthn:
	cd contracts && npx tsx e2e/coinbase/coinbase-webauthn.ts

e2e-light-account:
	cd contracts && npx tsx e2e/light-account/light-account-ecdsa.ts

e2e-negative-mempool:
	cd contracts && npx tsx e2e/negative/mempool-tracer.ts

e2e-negative-protocol:
	cd contracts && npx tsx e2e/negative/protocol-constraints.ts

e2e-mldsa:
	cd contracts && npx tsx e2e/mldsa/mldsa-basic.ts

e2e-eoa-batching:
	cd contracts && npx tsx e2e/eoa/eoa-batching.ts

e2e-eoa-sponsor:
	cd contracts && npx tsx e2e/eoa/eoa-sponsor.ts

e2e-eoa-p256:
	cd contracts && npx tsx e2e/eoa/eoa-p256.ts

e2e-eoa: e2e-eoa-batching e2e-eoa-sponsor e2e-eoa-p256

e2e-negative: e2e-negative-mempool e2e-negative-protocol

e2e:
	cd contracts && npx tsx e2e/run-all.ts

benchmark:
	cd contracts && npx tsx e2e/benchmark/gas-benchmark.ts

clean: clean-geth clean-solc clean-viem

clean-geth:
	rm -f $(GETH_BIN)
	$(MAKE) -C 8141-geth clean

clean-solc:
	rm -f $(SOLC_BIN)
	rm -rf $(BUILD_DIR)/solc

clean-viem:
	cd viem-eip8141 && pnpm clean
