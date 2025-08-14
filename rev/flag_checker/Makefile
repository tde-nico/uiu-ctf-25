#####   COLORS   #####

END				= \033[0m

GREY			= \033[30m
RED				= \033[31m
GREEN			= \033[32m
YELLOW			= \033[33m
BLUE			= \033[34m
PURPLE			= \033[35m
CYAN			= \033[36m

HIGH_RED		= \033[91m

#####   INFO   #####

NAME			= solve

#####   COMMANDS   #####

CC				= nvcc
CFLAGS			= -g --use_fast_math -rdc=true

MD				= mkdir -p
RM				= rm -rf


#####   RESOURCES   #####

SRC_DIR			= srcs
OBJ_DIR			= objs

SRC_SUB_DIRS	= $(shell find $(SRC_DIR) -type d)
OBJ_SUB_DIRS	= $(SRC_SUB_DIRS:$(SRC_DIR)%=$(OBJ_DIR)%)

SRCS			= $(foreach DIR, $(SRC_SUB_DIRS), $(wildcard $(DIR)/*.cu))
OBJS			= $(SRCS:$(SRC_DIR)/%.cu=$(OBJ_DIR)/%.o)



#####   BASE RULES   #####

all: $(NAME)

$(NAME): $(OBJ_SUB_DIRS) $(OBJS)
	@ $(CC) $(CFLAGS) $(OBJS) -o $@
	@ echo "$(GREEN)[+] $(NAME)$(END)"

$(OBJ_DIR)/%.o : $(SRC_DIR)/%.cu $(INCS)
	@ $(CC) $(CFLAGS) -c $< -o $@
	@ echo "$(BLUE)[+] $@$(END)"

$(OBJ_SUB_DIRS):
	@ $(MD) $(OBJ_SUB_DIRS)
	@ echo "$(PURPLE)[+] $(SRC_DIR) -> $(OBJ_DIR) $(END)"


clean:
	@ $(RM) $(OBJ_DIR)
	@ echo "$(YELLOW)[+] $(OBJ_DIR)$(END)"

fclean: clean
	@ $(RM) $(NAME)
	@ echo "$(YELLOW)[+] $(NAME)$(END)"

re: fclean all



#####   EXTRA RULES   #####

test: all
	@ ./$(NAME)

run: test
rrun: fclean test


#####   PHONY   #####

.PHONY: all clean fclean re bonus test run rrun