APP := dahash
CMD := ./cmd/dahash
PREFIX ?= $(HOME)/.local
BINDIR ?= $(PREFIX)/bin
CONFIG_HOME ?= $(HOME)/.config
CONFIGDIR ?= $(CONFIG_HOME)/$(APP)
DATADIR ?= $(CONFIGDIR)/data
DESTDIR ?=
GO ?= go
GOFLAGS ?= -trimpath
MKDIR ?= mkdir -p
CP ?= cp -R
RM ?= rm -f
RM_RF ?= rm -rf

.PHONY: all build install install-bin install-data uninstall test fixtures clean

all: build

build:
	$(GO) build $(GOFLAGS) -o $(APP) $(CMD)

install: install-bin install-data

install-bin:
	$(MKDIR) "$(DESTDIR)$(BINDIR)"
	$(GO) build $(GOFLAGS) -o "$(DESTDIR)$(BINDIR)/$(APP)" $(CMD)

install-data:
	$(RM_RF) "$(DESTDIR)$(DATADIR)/hash-types"
	$(MKDIR) "$(DESTDIR)$(DATADIR)"
	$(CP) data/hash-types "$(DESTDIR)$(DATADIR)/hash-types"

uninstall:
	$(RM) "$(DESTDIR)$(BINDIR)/$(APP)"
	$(RM_RF) "$(DESTDIR)$(DATADIR)/hash-types"

test:
	$(GO) test ./...

fixtures:
	bash test/run-all.sh

clean:
	$(RM) $(APP)
