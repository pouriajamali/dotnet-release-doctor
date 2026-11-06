// Benign, synthetic test-only target. The doctor must never execute this program.
File.WriteAllText("TRIPWIRE_ENTRY_EXECUTED", "The target entry was executed.");
Console.WriteLine("Tripwire executed; not an inspector action.");
