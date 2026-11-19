// Language / package-ecosystem profiles used to prioritise relevant CVEs.
export const ECOSYSTEMS = {
  npm: {
    label: "JavaScript/TypeScript (npm, Node.js)",
    targetSw: ["node.js", "nodejs", "node"],
    keywords: ["npm package", "node.js"],
    upgrade: (n, v) => `npm install ${n}@${v}`,
    transitiveHint: (n, v) =>
      `transitive: run \`npm ls ${n}\` to find the parent, upgrade the parent, or add "overrides": { "${n}": "${v}" } to package.json (yarn: "resolutions", pnpm: "pnpm.overrides").`,
  },
  pypi: {
    label: "Python (PyPI)",
    targetSw: ["python"],
    keywords: ["pypi", "python package"],
    upgrade: (n, v) => `pip install "${n}>=${v}"  (then pin in requirements.txt: ${n}==${v} or newer)`,
    transitiveHint: (n, v) => `transitive: add an explicit constraint "${n}>=${v}" to requirements/constraints.txt.`,
  },
  go: {
    label: "Go modules",
    targetSw: ["go", "golang"],
    keywords: ["golang", "go module"],
    upgrade: (n, v) =>
      n === "stdlib" || n === "toolchain"
        ? `go get toolchain@go${v.replace(/^v/, "")}  (sets the toolchain line in go.mod; also update CI images / Dockerfile, then rebuild)`
        : `go get ${n}@v${v.replace(/^v/, "")} && go mod tidy`,
    transitiveHint: (n, v) => `indirect: go get ${n}@v${v.replace(/^v/, "")} && go mod tidy`,
  },
  maven: {
    label: "Java (Maven/Gradle)",
    targetSw: ["java"],
    keywords: ["maven", "java library"],
    upgrade: (n, v) => `bump ${n} to ${v} in pom.xml / build.gradle (or dependencyManagement / constraints for transitive)`,
  },
  composer: {
    label: "PHP (Composer)",
    targetSw: ["php"],
    keywords: ["composer package", "php library"],
    upgrade: (n, v) => `composer require ${n}:^${v}`,
  },
  rubygems: {
    label: "Ruby (RubyGems)",
    targetSw: ["ruby", "rails"],
    keywords: ["ruby gem", "rubygems"],
    upgrade: (n, v) => `bundle update ${n}  (Gemfile: gem "${n}", ">= ${v}")`,
  },
  cargo: {
    label: "Rust (crates.io)",
    targetSw: ["rust"],
    keywords: ["rust crate", "crates.io"],
    upgrade: (n, v) => `cargo update -p ${n} --precise ${v}  (or bump in Cargo.toml)`,
  },
  nuget: {
    label: ".NET / C# (NuGet)",
    targetSw: [".net", "asp.net", ".net_framework", ".net_core"],
    keywords: ["nuget", ".net"],
    upgrade: (n, v) => `dotnet add package ${n} --version ${v}  (central package management: update <PackageVersion Include="${n}"> in Directory.Packages.props)`,
    transitiveHint: (n, v) => `transitive: add a direct <PackageReference Include="${n}" Version="${v}" /> (or enable CentralPackageTransitivePinningEnabled with a PackageVersion entry).`,
  },
  pub: {
    label: "Dart / Flutter (pub)",
    targetSw: ["dart", "flutter"],
    keywords: ["dart package", "flutter"],
    upgrade: (n, v) => `dart pub add ${n}:^${v}  (Flutter: flutter pub add ${n}:^${v})`,
    transitiveHint: (n, v) => `transitive: add dependency_overrides: { ${n}: ^${v} } to pubspec.yaml or upgrade the parent package (dart pub deps).`,
  },
  hex: {
    label: "Elixir / Erlang (Hex)",
    targetSw: ["elixir", "erlang"],
    keywords: ["elixir", "hex package"],
    upgrade: (n, v) => `update mix.exs to {:${n}, "~> ${v}"} and run mix deps.update ${n}`,
    transitiveHint: (n, v) => `transitive: add {:${n}, "~> ${v}", override: true} to mix.exs deps.`,
  },
  swift: {
    label: "Swift (SwiftPM)",
    targetSw: ["swift", "iphone_os", "macos"],
    keywords: ["swift package", "swiftpm"],
    upgrade: (n, v) => `update .package(url: "https://${n}", from: "${v}") in Package.swift and run swift package update`,
  },
  cran: {
    label: "R (CRAN)",
    targetSw: ["r"],
    keywords: ["r package", "cran"],
    upgrade: (n, v) => `install.packages("${n}") (>= ${v}) then renv::snapshot()`,
  },
};

export const ECOSYSTEM_ALIASES = {
  javascript: "npm", typescript: "npm", node: "npm", nodejs: "npm", "node.js": "npm", js: "npm", ts: "npm",
  python: "pypi", pip: "pypi", py: "pypi",
  golang: "go",
  java: "maven", gradle: "maven", kotlin: "maven",
  php: "composer",
  ruby: "rubygems", gem: "rubygems", rails: "rubygems",
  rust: "cargo", crates: "cargo",
  dotnet: "nuget", ".net": "nuget", csharp: "nuget", "c#": "nuget", fsharp: "nuget", "f#": "nuget", vb: "nuget",
  dart: "pub", flutter: "pub",
  elixir: "hex", erlang: "hex", mix: "hex",
  swiftpm: "swift", ios: "swift",
  r: "cran", renv: "cran",
};

export function resolveEcosystem(name) {
  if (!name) return null;
  const k = String(name).toLowerCase().trim();
  if (ECOSYSTEMS[k]) return k;
  return ECOSYSTEM_ALIASES[k] || null;
}

/** relevance of a CPE target_sw to an ecosystem: 2 = exact, 1 = unspecified, 0 = other platform */
export function targetSwRelevance(targetSw, eco) {
  if (!eco) return 1;
  if (!targetSw || targetSw === "*" || targetSw === "-") return 1;
  return ECOSYSTEMS[eco].targetSw.includes(targetSw.toLowerCase()) ? 2 : 0;
}
