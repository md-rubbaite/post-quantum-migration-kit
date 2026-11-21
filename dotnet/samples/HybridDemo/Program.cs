using QuantumSafe.Crypto;

// Configuration decides the algorithm; the code below never names one.
var policy = new CryptoPolicy(KeyEstablishmentMode.Hybrid, RequirePostQuantum: args.Contains("--require-pqc"));

Console.WriteLine($"ML-KEM available: {PqcSupport.MlKemAvailable}");
Console.WriteLine($"ML-DSA available: {PqcSupport.MlDsaAvailable}");

PolicyDecision decision;
try
{
    decision = policy.Resolve();
}
catch (PostQuantumUnavailableException ex)
{
    Console.Error.WriteLine($"Refusing to continue: {ex.Message}");
    return 1;
}

Console.WriteLine($"Key establishment: {decision.Mode} ({decision.Reason})");

var scheme = decision.CreateScheme();
using var recipient = scheme.GenerateRecipient();
var message = "Patient record #1042: keep confidential until 2046"u8.ToArray();
var envelope = Envelope.Seal(scheme, recipient.PublicKey, message);
var opened = Envelope.Open(recipient, envelope);

Console.WriteLine($"Recipient public key: {recipient.PublicKey.Length} bytes");
Console.WriteLine($"Envelope: {envelope.Length} bytes for a {message.Length}-byte message");
Console.WriteLine($"Round trip OK: {opened.AsSpan().SequenceEqual(message)}");
return 0;
