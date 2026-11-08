# TrustAgent evidence interface

Mode: Operate. Built as static HTML, CSS and JavaScript served by the local Python
controller. User approved an event table with a side evidence inspector.

## Visual system

System sans text uses 15px base, 22px main heading, 18px inspector heading and
13px table content. Monospace is reserved for resource paths, identifiers and
measured values. Cool surfaces (#edf3f7, #ffffff, #f8fbfd) sit below navy navigation
(#153b5b). Text is #16334b with secondary #526879. Selection uses #e0eef8; green,
amber and red semantic states always include explicit text labels.

The desktop split pane gives activity slightly more width than evidence. Below
900px the inspector follows the table; below 540px filters stack and the run
controls span the available width. Table content can scroll independently.
Source evidence is a connected vertical list, with inferred exposure explicitly
named. Empty, filtered-empty, disconnected, stopping, stopped and unknown states
are part of the interface. Controls use visible keyboard focus and reduced-motion
preferences are honored.

## Verification

The live browser verification exercised real run events, source evidence, search
empty state, 390px layout without horizontal overflow and the STOP control.
Docker subsequently confirmed both containers exited. Desktop/mobile images and
the machine-readable results are in the ignored `.runtime/ui-verification/`.

The design detector reported one cramped-padding warning on the outer split-pane
wrapper. Visual inspection confirmed section headings have 24px padding and table
cells have their own insets; the wrapper intentionally frames these subregions.
The warning is recorded as a reviewed false positive, not a missing green check.
No shipping raster assets or generated imagery are used.
