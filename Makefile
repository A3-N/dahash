APP := dahash
CMD := ./cmd/dahash
PREFIX ?= $(HOME)/.local
BINDIR ?= $(PREFIX)/bin
DESTDIR ?=
GO ?= go
GOFLAGS ?= -trimpath
MKDIR ?= mkdir -p
RM ?= rm -f

.PHONY: all build install uninstall test fixtures clean

all: build

build:
	$(GO) build $(GOFLAGS) -o $(APP) $(CMD)

install:
	$(MKDIR) "$(DESTDIR)$(BINDIR)"
	$(GO) build $(GOFLAGS) -o "$(DESTDIR)$(BINDIR)/$(APP)" $(CMD)

uninstall:
	$(RM) "$(DESTDIR)$(BINDIR)/$(APP)"

test:
	$(GO) test ./...

fixtures:
	bash test/run-all.sh

clean:
	$(RM) $(APP)
