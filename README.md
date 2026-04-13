# Layered Anti-Reverse Engineering Loader

A layered anti-analysis and anti-reverse engineering project focused on protecting a game loader and its runtime environment.

This project is built around one core idea: a single protection mechanism is never enough.  
Instead of relying on one anti-debug or one blacklist, the loader combines multiple defensive layers that work together across process access, memory behavior, runtime inspection, watchdog monitoring, and fail-safe cleanup.

---

## Overview

This project contains:

- a protected loader
- encrypted payload handling
- runtime anti-analysis logic
- anti-debug and anti-tool monitoring
- memory-focused sabotage routines
- a watchdog/heartbeat guard process
- cleanup and fail-safe kill logic

The goal is to make runtime analysis, inspection, memory dumping, and debugger attachment significantly harder during execution.

---

## Main Design Approach

The system is designed as a layered defense model.

Instead of assuming one method will stop everything, it applies protection at several different points:

- before the game is launched
- while the game is running
- while the loader is alive
- when the loader is interrupted or killed
- when external tools attempt inspection
- when suspicious runtime behavior is detected

This helps reduce dependence on any single protection method.

---

## Key Features

### 1. Encrypted Payload Handling
The protected SWF payload is stored in encrypted form and only decrypted at runtime before launch. The loader includes an AES-based decryption path for the embedded resource and writes the decrypted payload into the temporary game folder during execution. :contentReference[oaicite:2]{index=2}

### 2. Process Hardening
The loader applies process-level protections such as:
- handle access restrictions
- process/job object association
- mitigation-related controls
- reduced visibility/access to important runtime targets

The project also includes explicit handle-locking logic intended to make external process access harder. :contentReference[oaicite:3]{index=3}

### 3. Anti-Debug / Anti-Analysis Monitoring
The runtime includes multiple detection layers for:
- debugger presence
- remote debugger attachment
- known analysis tools
- common decompiler/runtime inspection tooling
- suspicious process titles and names

These checks are intentionally layered rather than isolated. :contentReference[oaicite:4]{index=4}

### 4. Memory-Oriented Protection
The loader includes memory-aware logic intended to interfere with analysis and dumping workflows, including:
- memory integrity style checks
- injected thread detection
- region scanning behavior
- SWF header corruption in memory after launch
- memory-map disruption logic designed to make external inspection less reliable

This is one of the more aggressive parts of the project and reflects a runtime anti-dump / anti-inspection approach rather than only static hiding. :contentReference[oaicite:5]{index=5}

### 5. Watchdog / Heartbeat Guard
A separate guard executable monitors a heartbeat file and reacts if the protected process chain becomes invalid or stale. The watchdog tracks:
- heartbeat freshness
- loader PID
- game PID
- suspicious tool presence

If the heartbeat dies or the runtime becomes invalid, the guard can kill the game process and trigger a strong fail-safe response. :contentReference[oaicite:6]{index=6}

### 6. Cleanup and Failsafe Logic
The project contains aggressive shutdown and cleanup routines intended to:
- kill the protected game process
- clean temporary artifacts
- invalidate the active runtime environment
- remove residual launch state where possible

This is designed as a fail-closed system rather than a permissive one. :contentReference[oaicite:7]{index=7}

---

## Architecture

### Loader
The loader is responsible for:
- validating runtime conditions
- decrypting the protected asset
- extracting/launching the game runtime
- applying early monitoring layers
- starting the watchdog
- maintaining heartbeat updates
- handling emergency cleanup

### Guard / Watchdog
The guard process is responsible for:
- monitoring the heartbeat file
- checking whether the loader/game process chain is still valid
- reacting when runtime state becomes stale
- killing the protected target if the protection state collapses

Together, these form a two-part defensive model:
- internal runtime protection
- external watchdog verification

---

## Protection Philosophy

This project does not treat reverse engineering as one single event.

It assumes analysis can happen through different paths:
- attaching a debugger
- opening a process handle
- suspending threads
- scanning memory
- dumping decrypted runtime content
- monitoring network/process behavior
- killing or bypassing the loader

Because of that, the protection logic tries to cover multiple attack surfaces instead of relying on one trick.

---

## Technical Themes

This project touches several technical areas:

- runtime decryption
- process access control
- anti-debug logic
- handle security and ACL-based restriction
- thread inspection
- memory inspection countermeasures
- watchdog-based process supervision
- temporary runtime staging
- cleanup and fail-safe shutdown behavior

---

## Notes

This project is experimental and intentionally aggressive in its design.

It is not meant to be a lightweight or user-friendly protection wrapper.  
It is built from the perspective of resisting analysis, interfering with inspection, and maintaining control over the runtime lifecycle as tightly as possible.

Because of that, parts of the project prioritize protection behavior over convenience.

---

## Author

Fırat Akyol

---

## Final Note

The implementation side of the project is AI-assisted, but the underlying ideas, structure, layering, and defensive design decisions are fully my own.

The focus of this project was never just “making it work.”  
It was about thinking through the smallest details of how a protected runtime behaves, how it fails, how it gets analyzed, and how multiple layers can be combined into a more resilient design.
