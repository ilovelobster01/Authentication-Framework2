# Convenience make targets for local dev

.PHONY: ca-init issue-server issue-client revoke-client up restart-nginx clean

ca-init:
	bash scripts/ca/init_ca.sh

issue-server:
	bash scripts/ca/issue_server.sh localhost

issue-client:
	@if [ -z "$(USER)" ]; then echo "Usage: make issue-client USER=<name> EMAIL=<email>"; exit 1; fi
	@if [ -z "$(EMAIL)" ]; then echo "Usage: make issue-client USER=<name> EMAIL=<email>"; exit 1; fi
	bash scripts/ca/issue_client.sh $(USER) $(EMAIL)

revoke-client:
	@if [ -z "$(CRT)" ]; then echo "Usage: make revoke-client CRT=path/to/cert.crt"; exit 1; fi
	bash scripts/ca/revoke_client.sh $(CRT)

up:
	docker compose up --build

restart-nginx:
	docker compose restart nginx

clean:
	rm -rf scripts/ca/out/server scripts/ca/out/clients
