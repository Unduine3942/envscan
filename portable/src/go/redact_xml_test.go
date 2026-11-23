// redact_xml_test.go: LINE RULES "xml" and the xml part of TEXT RULES "multi-line" (the XML_CASES
// of tests/redaction_cases.py, plus Go-only edge cases of the start-tag scanner).
package main

import (
	"strings"
	"testing"
	"time"
)

var redactXMLCases = []struct {
	name, op string
	in, want string
}{
	{"xml_cdata", "line", "<password><![CDATA[s3cret]]></password>", "<password><redacted></password>"},
	{"xml_ns_prefix", "line", "<ns:password>s3cret</ns:password>", "<ns:password><redacted></ns:password>"},
	{"xml_slash_in_attribute", "line", `<password xmlns="http://x/y">s3cret</password>`, `<password xmlns="http://x/y"><redacted></password>`},
	{"xml_unclosed_content", "line", "<password>s3cret", "<password><redacted>"},
	{"xml_unclosed_content_mid_line", "line", "usage: tool <token> [opts]", "usage: tool <token><redacted>"},
	{"xml_self_closing_kept", "line", `<token/> <token /> <password a="b/c"/>`, `<token/> <token /> <password a="b/c"/>`},
	{"xml_empty_element", "line", "<password></password>", "<password><redacted></password>"},
	{"xml_text_content_spans_lines", "text", "<password>CanaryFirst\n  CanarySecond\n</password>\n<user>bob</user>",
		"<password><redacted>\n  <redacted>\n</password>\n<user>bob</user>"},
	{"xml_text_ns_open", "text", "<ns:clientSecret>\n  CanaryNs\n</ns:clientSecret>\n<x>1</x>",
		"<ns:clientSecret>\n  <redacted>\n</ns:clientSecret>\n<x>1</x>"},
	{"xml_text_attr_slash_open", "text", "<password xmlns=\"http://a/b\">\n  CanaryAttr\n</password>\nok",
		"<password xmlns=\"http://a/b\">\n  <redacted>\n</password>\nok"},
	{"xml_text_cdata_spans_lines", "text", "  <password><![CDATA[\n  CanaryCdata\n  ]]></password>\nafter",
		"  <password><redacted>\n  <redacted>\n  <redacted></password>\nafter"},
	{"xml_text_mid_line_tag_does_not_open", "text", "usage: tool <token> [opts]\nnext line kept",
		"usage: tool <token><redacted>\nnext line kept"},
	// Go-only edge cases
	{"xml_two_elements", "line", "<token>a</token><password>b</password>", "<token><redacted></token><password><redacted></password>"},
	{"xml_word_after_name", "line", "<passwordHint>x</passwordHint>", "<passwordHint>x</passwordHint>"},
	{"xml_bad_prefix", "line", "<1ns:password>x</1ns:password>", "<1ns:password>x</1ns:password>"},
	{"xml_dotted_prefix", "line", "<a.b-c:Token>x</a.b-c:Token>", "<a.b-c:Token><redacted></a.b-c:Token>"},
	{"xml_no_gt", "line", "<password attr", "<password attr"},
	{"xml_blank_rest", "line", "<password>   ", "<password>   "},
	{"xml_nested_content", "line", "<secret><v>1</v></secret>", "<secret><redacted></secret>"},
	{"xml_text_ns_close_needed", "text", "<ns:token>\n  a\n</token>\n  b\n</ns:token>\nc",
		"<ns:token>\n  <redacted>\n<redacted>\n  <redacted>\n</ns:token>\nc"},
	{"xml_text_self_closing_no_open", "text", "<token/>\nkept", "<token/>\nkept"},
	{"xml_text_first_on_line_opens", "text", "  <token>abc\n  more\n  </token>\nkept",
		"  <token><redacted>\n  <redacted>\n  </token>\nkept"},
	{"xml_text_closed_on_line", "text", "  <token>abc</token>\nkept", "  <token><redacted></token>\nkept"},
	// review fixes 2026-11-15 (X1 a-h)
	{"xml_own_close_prefixed", "line", "<ns:password>a</password>b</ns:password>", "<ns:password><redacted></ns:password>"},
	{"xml_own_close_after_other", "line", "<password>a</x>b</password><token>c</token>",
		"<password><redacted></password><token><redacted></token>"},
	{"xml_prefix_not_element", "line", "<token:x>a</token:x>", "<token:<redacted>>"},
	{"xml_quoted_gt_self_closing", "line", `<password a="/>"/>`, `<password a="/>"/>`},
	{"xml_slash_then_space", "line", `<password a="x"/ >s</password>`, `<password a="x"/ ><redacted></password>`},
	{"xml_quote_unterminated_left", "line", `<password a="x>secret`, `<password a="x>secret`},
	{"xml_comment_unterminated_hides", "line", "<password>a<!-- </password>", "<password><redacted>"},
	{"xml_comment_then_next_close", "line", "<password>a<!-- x --></b>c", "<password><redacted></b>c"},
	{"xml_comment_hides_both", "line", "<password>a<!-- </password> </b> -->b", "<password><redacted>"},
	{"xml_non_ascii_before", "line", "\u0130\u0130<password>x</password>", "\u0130\u0130<password><redacted></password>"},
	{"xml_nbsp_rest_not_blank", "line", "<password>\u00a0", "<password><redacted>"},
	{"xml_text_first_unclosed_closed_later", "text", "<token>a</token> <password>\nCanaryL\n</password>",
		"<token><redacted></token> <password>\n<redacted>\n</password>"},
	{"xml_text_mid_unclosed_stops", "text", "x <token> y <password>\nkept\n</password>",
		"x <token><redacted>\nkept\n</password>"},
	{"xml_text_rescan_line_rules", "text", "<token>\nq\n</token> password=CanaryR",
		"<token>\n<redacted>\n</token> password=<redacted>"},
	{"xml_text_rescan_opens_again", "text", "<token>\nq\n</token>\t<secret>\nCanaryS\n</secret>\nend",
		"<token>\n<redacted>\n</token>\t<secret>\n<redacted>\n</secret>\nend"},
	{"xml_text_close_in_comment_then_real", "text", "<token>\nq <!-- </token> --> r</token> z",
		"<token>\n<redacted></token> z"},
	{"xml_text_split_quote_spans", "text", "<password a=\"x>y\nz\">CanaryQ\n</password>\nok",
		"<password a=\"x>y\nz\"><redacted>\n</password>\nok"},
	{"xml_text_split_single_quote", "text", "<password a='1\n>2'>\nCanaryQ2\n</password>\nok",
		"<password a='1\n>2'>\n<redacted>\n</password>\nok"},
	{"xml_text_split_close_same_line", "text", "  <token\n  b=\"1\">CanaryT</token> <x>k</x>\nok",
		"  <token\n  b=\"1\"><redacted></token> <x>k</x>\nok"},
	{"xml_text_split_attr_line_rules", "text", "<token\n  password=\"CanaryAttr\"\n>v</token>",
		"<token\n  password=<redacted>\n><redacted></token>"},
	{"xml_text_split_abandoned_indented", "text", "<secret a=\"1\"\n  <b>keep</b>\nkeep2",
		"<secret a=\"1\"\n  <b>keep</b>\nkeep2"},
	{"xml_text_split_self_closing", "text", "<token\n a=\"1\"/>\nkeep", "<token\n a=\"1\"/>\nkeep"},
	{"xml_line_split_left_alone", "line", "<token a=\"1\"", "<token a=\"1\""},
	// "<a:element" / "</a:element" (an xml_elements name after ":") is not a key/value pair;
	// "<password:x" and "<password: x" still are
	{"xml_qname_not_pair_value", "value", "<token:password>x</token:password>", "<token:password>x</token:password>"},
	{"xml_qname_space_is_pair", "value", "<password: hunter2>", "<password: <redacted>>"},
	{"xml_qname_pair_after_text", "value", "a password:hunter2", "a password:<redacted>"},
	{"xml_qname_local_not_element", "value", "<password:hunter2>", "<password:<redacted>>"},
	{"xml_qname_close_element", "value", "</ns:clientSecret>", "</ns:clientSecret>"},
	{"xml_qname_element_word_after", "value", "<token:passwordx>", "<token:<redacted>>"},
}

func TestRedactXMLCases(t *testing.T) {
	ops := map[string]func(string) string{"line": redactLine, "text": redactText, "value": redactValue}
	for _, c := range redactXMLCases {
		if got := ops[c.op](c.in); got != c.want {
			t.Errorf("%s (%s %q):\n got  %q\n want %q", c.name, c.op, c.in, got, c.want)
		}
		if got := ops[c.op](ops[c.op](c.in)); got != c.want && c.op == "line" {
			t.Errorf("%s twice: %q", c.name, got)
		}
	}
}

// Hostile start tags up to the length cap stay linear.
func TestRedactXMLHostileIsFast(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	units := []string{"<a:", "<a:password", "<password ", "<password/", "<ns:token a=\"/\"", "</", "<a.b.c",
		"<password a=\"", "<password a='", "<password>a</x>", "<!--", "<password>a<!--", "-->", "<password a=\">\"",
		"<token:password>a</b>", "<password:x>", "</password", "<password\n", "<password>\n</password>"}
	for _, unit := range units {
		in := strings.Repeat(unit, redactMaxLen/len(unit))
		for name, f := range map[string]func(string) string{"line": redactLine, "text": redactText} {
			t0 := time.Now()
			f(in)
			if d := time.Since(t0); d > 2*time.Second {
				t.Errorf("%s on %q took %v", name, unit, d)
			}
		}
	}
}

// Distinct namespace prefixes (one closing-tag key each) and unclosed quotes over many lines stay
// linear too.
func TestRedactXMLHostilePrefixesAreFast(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	var b strings.Builder
	for i := 0; b.Len() < redactMaxLen-80; i++ {
		b.WriteString("<p" + strings.Repeat("x", i%50) + itoa(i) + ":password>a</q>")
	}
	lines := strings.Repeat("<password a=\"x\n"+strings.Repeat("y", 200)+"\n", 3000)
	for name, in := range map[string]string{"prefixes": b.String(), "quote lines": lines} {
		for op, f := range map[string]func(string) string{"line": redactLine, "text": redactText} {
			t0 := time.Now()
			f(in)
			if d := time.Since(t0); d > 2*time.Second {
				t.Errorf("%s %s took %v", op, name, d)
			}
		}
	}
}
