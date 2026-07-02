"""ENC-ISS-441 / ENC-TSK-J96: terminal-state retirement nudge (checkout service side).

The nudge is injected via _with_retirement_prompt at the two advance return sites
(task -> closed, plan -> complete). These tests pin the exact io-specified prompt
text and the presence/absence semantics per terminal state; the wire-level envelope
is exercised on gamma (ENC-TSK-J98).
"""
import unittest

import lambda_function as checkout_lambda

_IO_PROMPT = (
    "Prompt the user if this session can now be retired, or retire the session if it "
    "is certain that the full scope of the current session assignment is complete."
)


class RetirementPromptTests(unittest.TestCase):
    def test_prompt_text_is_the_exact_io_specified_string(self):
        self.assertEqual(checkout_lambda.RETIREMENT_PROMPT, _IO_PROMPT)

    def test_task_closed_gets_prompt(self):
        env = checkout_lambda._with_retirement_prompt({"success": True}, "closed")
        self.assertEqual(env["retirement_prompt"], _IO_PROMPT)

    def test_plan_complete_gets_prompt(self):
        env = checkout_lambda._with_retirement_prompt(
            {"success": True}, "complete", terminal_statuses=("complete",)
        )
        self.assertEqual(env["retirement_prompt"], _IO_PROMPT)

    def test_non_terminal_statuses_untouched(self):
        for status in ("coding-complete", "committed", "pr", "merged-main",
                       "deploy-init", "deploy-success", "in-progress"):
            env = checkout_lambda._with_retirement_prompt({"success": True}, status)
            self.assertNotIn("retirement_prompt", env, status)

    def test_plan_incomplete_is_not_nudged(self):
        # 'incomplete' is an abandonment terminal, not a completed-scope terminal —
        # the io design nudges only on success-shaped finals.
        env = checkout_lambda._with_retirement_prompt(
            {"success": True}, "incomplete", terminal_statuses=("complete",)
        )
        self.assertNotIn("retirement_prompt", env)


if __name__ == "__main__":
    unittest.main()
