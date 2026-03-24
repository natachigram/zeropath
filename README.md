# Zeropath

Zeropath is an autonomous smart contract security research system designed to discover real, exploitable vulnerabilities in DeFi protocols.

Unlike traditional tools that rely on pattern matching or static analysis, Zeropath models protocols as financial systems, infers their core invariants, and actively searches for ways to break them through adversarial reasoning and simulation.

The goal is simple:

Find only what is real. Reject everything else.

---

## Core Philosophy

Zeropath does not attempt to list possible issues.

It attempts to answer one question:

> How can an attacker extract more value than they put in?

To achieve this, Zeropath behaves as both:

* an adversarial attacker searching for profit
* a strict audit judge rejecting weak or invalid findings

Every discovered issue must survive full system-level validation.

---

## Key Capabilities

### Protocol Understanding

* Parses and models smart contracts as a unified system
* Builds call graphs, storage mappings, and value flow representations
* Tracks how value enters, moves through, and exits the protocol

---

### Invariant Inference

* Automatically infers critical system invariants such as:

  * value conservation
  * share-to-asset consistency
  * collateralization constraints
* Links invariants to the exact state variables and functions that maintain them

---

### Adversarial Exploration

* Generates attack hypotheses from invariant violations
* Explores multi-step, cross-function interactions
* Tests edge cases, ordering effects, and repeated actions

---

### Economic Simulation

* Executes attack sequences in realistic environments
* Models liquidity, pricing, and external dependencies
* Evaluates attacker profit under real constraints

---

### Exploit Validation

* Rejects false positives aggressively
* Ensures:

  * no privileged roles required
  * realistic conditions
  * measurable profit
* Confirms invariant is broken at the system level, not locally

---

### Knowledge Evolution

* Learns from real-world audit reports
* Extracts generalized exploit primitives
* Recombines and mutates attack strategies to discover new vulnerability classes

---

## System Architecture

Zeropath is built as a multi-stage system:

1. Protocol Ingestion
2. Protocol Graph Construction
3. Invariant Inference
4. Attack Hypothesis Generation
5. Transaction Sequence Generation
6. Simulation Engine
7. Exploit Validation
8. Knowledge Graph & Learning Loop

Each stage is designed to be modular and extensible.

---

## What Makes Zeropath Different

Most tools:

* scan for known patterns
* analyze functions in isolation
* produce high false positives

Zeropath:

* reasons about the entire protocol
* focuses on invariant violations
* validates exploits through execution
* rejects weak findings before output

It does not aim to find more issues.

It aims to find fewer, but real ones.

---

## Design Principles

* System-level reasoning over local analysis
* Profit-driven validation over theoretical bugs
* Skepticism over speculation
* Iterative exploration over one-pass analysis
* Real-world exploitability over academic correctness

---

## Current Status

Zeropath is under active development.

Core components being built:

* protocol graph engine
* invariant inference module
* adversarial reasoning system
* simulation and validation pipeline

---

## Vision

Zeropath aims to become an autonomous security research system capable of:

* discovering unknown exploit techniques
* validating attacks under real conditions
* continuously learning from past vulnerabilities

Not just assisting auditors, but operating as a true research partner.

---

## Disclaimer

Zeropath is intended strictly for security research, auditing, and improving the safety of decentralized systems.

Any misuse of this system is the sole responsibility of the user.
