CC = gcc
CFLAGS = -Wall -Iinclude -g -DHAVE_XLSXIO=0 `pkg-config --cflags gtk4 poppler-glib libxml-2.0`
LIBS = -lcurl -lyaml -lcjson `pkg-config --libs gtk4 poppler-glib libxml-2.0`
TEST_LIBS = -lm -pthread -lrt

SRC = src/main.c src/ai_payload_generator.c src/attack_executor.c src/response_analyzer.c src/logger.c src/red_blue_interface.c src/config_parser.c src/ui.c src/utils.c src/rag_processor.c
OBJ = $(SRC:.c=.o)
EXEC = ai_attack_simulator

TEST_SRC = tests/test_payloads.c tests/test_attacks.c tests/test_analyzer.c
TEST_OBJ = $(TEST_SRC:.c=.o)
TEST_EXEC = $(TEST_SRC:.c=)

all: $(EXEC)

$(EXEC): $(OBJ)
	$(CC) $(OBJ) -o $@ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(EXEC) $(TEST_OBJ) $(TEST_EXEC)

test: $(TEST_EXEC)
	@for test in $(TEST_EXEC); do if [ -f $$test ]; then ./$$test; fi; done

tests/test_payloads: tests/test_payloads.c src/ai_payload_generator.o src/logger.o src/utils.o src/rag_processor.o src/config_parser.o
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS) $(TEST_LIBS)

tests/test_attacks: tests/test_attacks.c src/attack_executor.o src/logger.o src/utils.o
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS) $(TEST_LIBS)

tests/test_analyzer: tests/test_analyzer.c src/response_analyzer.o src/logger.o src/utils.o
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS) $(TEST_LIBS)

valgrind: $(EXEC)
	valgrind --leak-check=full ./$(EXEC)
