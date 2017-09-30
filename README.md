DynamoRIO Plugin
================

Miscellaneous DynamoRIO plugins

- `memtrace_simple`: original memtrace from the DynamoRIO repo, but ported to the
  `drx_buf` component
- `instrace_simple`: original instrace from the DynamoRIO repo, but ported to the
  `drx_buf` component
- `bbtrace_simple`: drcov-like plugin, but does a basic block *trace*. Has an option,
  `-only_from_app` to not trace library code
