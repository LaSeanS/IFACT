# IFACT

The Ignition Forensic Artifact Carving Tool (IFACT)  is a specialized forensic analysis tool that utilizes data carving techniques to extract critical system artifacts from Ignition SCADA environment files. Tailored for incident response and digital forensics investigations, this tool automates the parsing of network, disk, and memory-related data artifacts, enabling rapid analysis of system behavior and an overview of the system structure.

Key features include:

- Network Artifact Parsing: Extracts device communication server configurations and tag event data to analyze SCADA network activity.

- Disk Artifact Analysis: Recovers project files, gateway configurations, logs, PLC and tag data stored on disk. 

- Memory Artifact Parsing: Parses memory dumps from SCADA hosts to uncover tags being processed during runtime and PLC devices in active use.

IFACT supports structured output formats (e.g., JSON, CSV) for integration into analysis pipelines and hosts an HTML webserver for easy data viewing in the browser.
