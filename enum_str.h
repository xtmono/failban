/************** [ ENUM to STRING ] ***************
ENUM_TO_STR(color, RED, GREEN, BLUE, VIOLET);

// [enum -> str]
enum color c = VIOLET;
printf("%d -> %s\n", c, color_to_str(c));

// [str -> enum]
const char* color_name = "VIOLET";
enum color c = str_to_color(color_name);
printf("%s -> %d\n", color_name, c);
*************************************************/

#ifndef ENUM_STR_H
#define ENUM_STR_H

#ifdef __cplusplus
extern "C" {
#endif

#include <string.h>

#define NUMARGS(...) (sizeof((int[]){__VA_ARGS__})/sizeof(int))
#define ENUM_TO_STR(ENUM_NAME, ...)                                            \
	enum ENUM_NAME { __VA_ARGS__ };                                            \
	char ENUM_NAME##_strs[] = #__VA_ARGS__;                                    \
	long ENUM_NAME##_strs_idx[NUMARGS(__VA_ARGS__)];                           \
	__attribute__((constructor))                                               \
	void init_##ENUM_NAME##_strs(void) {                                       \
		size_t i = 0, index = 0;                                               \
		ENUM_NAME##_strs_idx[i++] = 0;                                         \
		while (ENUM_NAME##_strs[index] != '\0' && i < NUMARGS(__VA_ARGS__)) {  \
			if (ENUM_NAME##_strs[index] == ',') {                              \
				ENUM_NAME##_strs[index] = '\0';                                \
				ENUM_NAME##_strs_idx[i++] = index + 1;                         \
				while (ENUM_NAME##_strs[ENUM_NAME##_strs_idx[i-1]] == ' ' ||   \
						ENUM_NAME##_strs[ENUM_NAME##_strs_idx[i-1]] == '\t')   \
					ENUM_NAME##_strs_idx[i-1]++;                               \
			}                                                                  \
			index++;                                                           \
		}                                                                      \
	}                                                                          \
	char *ENUM_NAME##_to_str(enum ENUM_NAME value) {                           \
		if (value >= 0 && value < NUMARGS(__VA_ARGS__))                        \
			return &ENUM_NAME##_strs[ENUM_NAME##_strs_idx[value]];             \
		return "UNKNOWN";                                                      \
	}                                                                          \
	enum ENUM_NAME str_to_##ENUM_NAME(const char* str) {                       \
		for (size_t i = 0; i < NUMARGS(__VA_ARGS__); i++) {                    \
			if (strcmp(str,                                                    \
					&ENUM_NAME##_strs[ENUM_NAME##_strs_idx[i]]) == 0)          \
				return (enum ENUM_NAME)i;                                      \
		}                                                                      \
		return -1;                                                             \
	}

#ifdef __cplusplus
}
#endif

#endif /* ENUM_STR_H */
