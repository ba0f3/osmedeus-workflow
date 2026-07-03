# =============================================================================
# Makefile — Osmedeus Workflow Development
# =============================================================================
# Install workflows to ~/osmedeus-base/workflows for local development.
# =============================================================================

BASE ?= $(HOME)/osmedeus-base
WORKFLOWS := $(BASE)/workflows
SRC := $(dir $(realpath $(firstword $(MAKEFILE_LIST))))

YELLOW := \033[1;33m
GREEN  := \033[1;32m
CYAN   := \033[1;36m
RED    := \033[1;31m
NC     := \033[0m

.PHONY: help install install-common install-fragments install-events install-flows lint diff status

help:
	@echo ""
	@echo "$(CYAN)Osmedeus Workflow Development Makefile$(NC)"
	@echo ""
	@echo "  $(GREEN)make install$(NC)        — Copy all workflows to $(WORKFLOWS)"
	@echo "  $(GREEN)make lint$(NC)          — Run osmedeus workflow lint on all YAML files"
	@echo "  $(GREEN)make diff$(NC)          — Show differences between local and installed"
	@echo "  $(GREEN)make status$(NC)        — Show deployment status (missing/newer files)"
	@echo ""

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------

install: install-common install-fragments install-events install-flows
	@echo ""
	@echo "$(GREEN)✔ All workflows installed to $(WORKFLOWS)$(NC)"

install-common:
	@mkdir -p $(WORKFLOWS)/common
	@echo "$(CYAN)  common/ → $(WORKFLOWS)/common/$(NC)"
	@cp $(SRC)common/*.yaml $(WORKFLOWS)/common/

install-fragments:
	@mkdir -p $(WORKFLOWS)/fragments
	@echo "$(CYAN)  fragments/ → $(WORKFLOWS)/fragments/$(NC)"
	@cp $(SRC)fragments/*.yaml $(WORKFLOWS)/fragments/

install-events:
	@mkdir -p $(WORKFLOWS)/events
	@echo "$(CYAN)  events/ → $(WORKFLOWS)/events/$(NC)"
	@cp $(SRC)events/*.yaml $(WORKFLOWS)/events/

install-flows:
	@echo "$(CYAN)  *.yaml → $(WORKFLOWS)/$(NC)"
	@cp $(SRC)*.yaml $(WORKFLOWS)/
	@echo "$(CYAN)  *.md → $(WORKFLOWS)/$(NC)"
	@cp $(SRC)README.md $(WORKFLOWS)/
	@cp $(SRC)AGENTS.md $(WORKFLOWS)/

# ---------------------------------------------------------------------------
# Lint
# ---------------------------------------------------------------------------

lint:
	@echo "$(CYAN)Linting all workflow YAML files...$(NC)"
	@failed=0; \
	for f in $$(find $(SRC) -maxdepth 1 -name '*.yaml' -not -path '*/node_modules/*' | sort); do \
		osmedeus workflow lint "$$f" > /tmp/.osm-lint-$$(basename $$f).log 2>&1; \
		if [ $$? -ne 0 ]; then \
			echo "  $(RED)✘$$(basename $$f)$(NC)"; \
			cat /tmp/.osm-lint-$$(basename $$f).log | grep -E "error|Error"; \
			failed=$$((failed + 1)); \
		else \
			echo "  $(GREEN)✔$$(basename $$f)$(NC)"; \
		fi; \
	done; \
	for dir in common fragments events; do \
		for f in $$(find $(SRC)$$dir -name '*.yaml' | sort); do \
			osmedeus workflow lint "$$f" > /tmp/.osm-lint-$$(basename $$f).log 2>&1; \
			if [ $$? -ne 0 ]; then \
				echo "  $(RED)✘ $$dir/$$(basename $$f)$(NC)"; \
				cat /tmp/.osm-lint-$$(basename $$f).log | grep -E "error|Error"; \
				failed=$$((failed + 1)); \
			else \
				echo "  $(GREEN)✔ $$dir/$$(basename $$f)$(NC)"; \
			fi; \
		done; \
	done; \
	rm -f /tmp/.osm-lint-*.log; \
	if [ $$failed -gt 0 ]; then \
		echo ""; \
		echo "$(RED)✘ $$failed file(s) failed lint$(NC)"; \
		exit 1; \
	fi; \
	echo ""; \
	echo "$(GREEN)✔ All files passed lint$(NC)"

# ---------------------------------------------------------------------------
# Diff / Status
# ---------------------------------------------------------------------------

diff:
	@echo "$(CYAN)Diff: local vs installed ($(WORKFLOWS))$(NC)"
	@diff -rq $(SRC) $(WORKFLOWS) \
		--exclude=.git --exclude=.github --exclude=.cursor --exclude=.gortex \
		--exclude=.agents --exclude=.codex \
		--exclude=.gitignore \
		--exclude=Makefile \
		--exclude=docs \
		2>/dev/null || true

status:
	@echo "$(CYAN)Deployment status:$(NC)"
	@echo ""
	@files=0; missing=0; outofdate=0; \
	for f in $$(find $(SRC) -name '*.yaml' -not -path '*/node_modules/*' | sort); do \
		rel=$${f#$(SRC)}; \
		installed=$(WORKFLOWS)/$$rel; \
		files=$$((files + 1)); \
		if [ ! -f "$$installed" ]; then \
			echo "  $(YELLOW)◌ missing:$$rel$(NC)"; \
			missing=$$((missing + 1)); \
		elif ! diff -q "$$f" "$$installed" >/dev/null 2>&1; then \
			echo "  $(YELLOW)~ updated: $$rel$(NC)"; \
			outofdate=$$((outofdate + 1)); \
		fi; \
	done; \
	for f in $(SRC)README.md $(SRC)AGENTS.md; do \
		rel=$${f#$(SRC)}; \
		installed=$(WORKFLOWS)/$$rel; \
		if [ ! -f "$$installed" ]; then \
			echo "  $(YELLOW)◌ missing:$$rel$(NC)"; \
			missing=$$((missing + 1)); \
		elif ! diff -q "$$f" "$$installed" >/dev/null 2>&1; then \
			echo "  $(YELLOW)~ updated: $$rel$(NC)"; \
			outofdate=$$((outofdate + 1)); \
		fi; \
	done; \
	echo ""; \
	echo "  $(GREEN)$$files$(NC) workflow files total"; \
	if [ $$missing -gt 0 ]; then echo "  $(YELLOW)$$missing missing$(NC) — run 'make install'"; fi; \
	if [ $$outofdate -gt 0 ]; then echo "  $(YELLOW)$$outofdate out of date$(NC) — run 'make install'"; fi; \
	if [ $$missing -eq 0 ] && [ $$outofdate -eq 0 ]; then echo "  $(GREEN)✔ All deployed and up to date$(NC)"; fi
