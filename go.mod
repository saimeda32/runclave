module github.com/saimeda/runclave

go 1.26

// Dependency policy (trust engineering, criterion T1): keep this near-empty.
// Every dependency is a reason for a supply-chain-paranoid user to distrust us.
// yaml.v3 is the single external dep, justified: policy packs are YAML (P1/P2),
// and hand-rolling a YAML parser would be more code and more risk than the dep.
require gopkg.in/yaml.v3 v3.0.1
