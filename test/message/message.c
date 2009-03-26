#include "message.h"

void test_text_to_html(const char *input, const char *output)
{
	char *result;

	result = gg_message_text_to_html(input, NULL, 0);

	if (result == NULL) {
		perror("gg_message_text_to_html");
		exit(1);
	}

	printf("text: \"%s\"\n", input);
	printf("output: \"%s\"\n", result);

	if (strcmp(result, output) == 0) {
		printf("correct\n\n");
		free(result);
	} else {
		printf("expected: \"%s\"\n", output);
		free(result);
		exit(1);
	}
}

void test_html_to_text(const char *input, const char *output)
{
	char *result;

	result = gg_message_html_to_text(input);

	if (result == NULL) {
		perror("gg_message_html_to_text");
		exit(1);
	}

	printf("html: \"%s\"\n", input);
	printf("output: \"%s\"\n", result);

	if (strcmp(result, output) == 0) {
		printf("correct\n\n");
		free(result);
	} else {
		printf("expected: \"%s\"\n", output);
		free(result);
		exit(1);
	}
}

int main(int argc, char **argv)
{
	test_text_to_html("<bzdura>\r\n\"ala&ma'kota\"", "<span style=\"font-family:'MS Shell Dlg 2'; font-size:9pt; \">&lt;bzdura&gt;<br>&quot;ala&amp;ma&apos;kota&quot;</span>");

	test_html_to_text("<span style=\"font-family:'MS Shell Dlg 2'; font-size:9pt; \">&lt;bzdura&gt;<br>&quot;ala&amp;ma&apos;kota&quot;</span>", "<bzdura>\r\n\"ala&ma'kota\"");

	return 0;
}
