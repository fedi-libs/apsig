---
icon: lucide/file
---

# Compatibility Report

This report summarizes the degree of compatibility between apsig and various ActivityPub implementations and HTTP Signatures implementations.

# 1. Overview
!!! note
    RFC9421 implementation is in progress, not merged to main code.

apsig tested in following implementations:

| Implementation | draft-cavage-http-signatures-12 | Linked Data Signatures 1.0 | FEP-8b32 | RFC9421 | Notes                                             | 
| -------------- | ------------------------------- | -------------------------- | -------- | ------- | ------------------------------------------------- | 
| Mastodon       | ✔                              | -                          | -        | -       | FEP-8b32 is not implemented.                      | 
| Misskey        | ✔                              | -                          | -        | -       | FEP-8b32 is not implemented.                      | 
| Fedify         | ✔                              | ✔                         | ✔       | ×       | apsig's implementation is tested in fedify first. | 

- `✔`: working correctly
- `×`: not working
- `-`: not tested