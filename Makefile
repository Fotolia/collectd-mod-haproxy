PREFIX=/usr/${EXTRA_PREFIX}
PLUGINDIR=${PREFIX}/lib/collectd
INCLUDEDIR=/usr/include/collectd/ ${EXTRA_INCLUDE}

CFLAGS=-I${INCLUDEDIR} -Wall -Werror -g -O2

bin:
	${CC} -DHAVE_CONFIG_H ${CFLAGS} -c haproxy.c  -fPIC -DPIC -o haproxy.o
	${CC} -shared  haproxy.o -Wl,-soname -Wl,haproxy.so -o haproxy.so

clean:
	rm -f haproxy.o haproxy.so

install:
	mkdir -p ${DESTDIR}/${PLUGINDIR}/
	cp haproxy.so ${DESTDIR}/${PLUGINDIR}/
