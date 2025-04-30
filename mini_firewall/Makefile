BPF_CLANG=clang
BPF_ECC=ecc
CFLAGS=-O2 -g -target bpf -D__TARGET_ARCH_x86

all: ingress.o package.json

ingress.o: ingress.c
	$(BPF_CLANG) -I . $(CFLAGS) -c $<

in.o: in.c
	$(BPF_CLANG) $(CFLAGS) -c $<

package.json: egress.c
	$(BPF_ECC) $<

load_xdp:
	sudo xdp-loader load -m skb -p /sys/fs/bpf test ingress.o

load_tc:
	sudo ecli run ./package.json

unload:
	- sudo xdp-loader unload test -a

status:
	sudo xdp-loader status

clean:
	rm -rf *.o *.json

run: all unload load_xdp load_tc
