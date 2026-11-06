# F146 — e2e time budget for debian13 needs a person's decision

`budgets.tsv` is a person's to set; the builder does not edit it and did not remove or skip cases to fit.

## Question
Raise the `e2e debian13` budget (now 430 s, measured 360 s before F135–F144) to roughly 700 s?

## Numbers (lone-run estimates, not measurements of the loop's 6-at-once run)
| target (swtpm) | lone wall | budget now | cases | verdict |
|---|---|---|---|---|
| debian13 | 605 s | 430 | 160 | over; M4 cases add about +270 s (F135 20, F136 22, F137 23, F139 62, F140 31, F143 50, F144 18, F142 m3 ~45) |
| debian13 (none) | 416 s | 430 | 160 | close; the loop runs it in parallel and it may pass 430 |
| alma10 | 357 s | 470 | 103 | under (lone) |
| arch | 307 s | 410 | 103 | under (lone) |
| fedora44 | 303 s | 500 | 103 | under (lone) |
| ubuntu2604 | 295 s | 460 | 112 | under (lone) |
| ubuntu2404 | 5 s | 100 | 5 | under (refusal only) |

The old budgets were measured with 6 runs at once; a lone run is shorter, so the parallel times are
probably higher than these. Requested: debian13 about 700 s (a parallel run is expected above the lone 605 s);
the other targets are likely fine, the loop's own check decides.

Everything else of F146 is done and green (see PROGRESS.md).
