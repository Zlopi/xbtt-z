g++ $@ -DNDEBUG -I /usr/local/include -I ../misc -I . -O3 -o xbt_tracker \
	-Wl,-R/usr/local/lib/gcc48 \
	../misc/sql/database.cpp \
	../misc/sql/sql_query.cpp \
	../misc/sql/sql_result.cpp \
	../misc/bt_misc.cpp \
	../misc/bvalue.cpp \
	../misc/sha1.cpp \
	../misc/socket.cpp \
	../misc/virtual_binary.cpp \
	../misc/xcc_z.cpp \
	md5.cpp \
	config.cpp \
	connection.cpp \
	epoll.cpp \
	server.cpp \
	tcp_listen_socket.cpp \
	tracker_input.cpp \
	transaction.cpp \
	udp_listen_socket.cpp \
	"XBT Tracker.cpp" \
	`mysql_config --libs` && strip xbt_tracker
