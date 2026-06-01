<?php

declare(strict_types=1);

namespace LaraMint\LaravelBrain\Analysis;

final class DddIssue
{
    public function __construct(
        public string $id,
        public string $rule,
        public string $severity,
        public string $module,
        public string $layer,
        public string $message,
        public string $file,
        public ?int $line = null,
    ) {}

    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'rule' => $this->rule,
            'severity' => $this->severity,
            'module' => $this->module,
            'layer' => $this->layer,
            'message' => $this->message,
            'file' => $this->file,
            'line' => $this->line,
        ];
    }
}

final class DddModule
{
    /**
     * @param  array<string, int>  $layerFileCounts
     * @param  list<DddIssue>  $issues
     */
    public function __construct(
        public string $name,
        public string $path,
        public array $layerFileCounts,
        public array $issues,
    ) {}

    public function issueCount(): int
    {
        return count($this->issues);
    }
}

final class DddAnalysisResult
{
    /**
     * @param  list<DddModule>  $modules
     * @param  list<DddIssue>  $issues
     */
    public function __construct(
        public array $modules,
        public array $issues,
    ) {}

    public function moduleCount(): int
    {
        return count($this->modules);
    }

    public function issueCount(): int
    {
        return count($this->issues);
    }
}

final class DddModuleAnalyzer
{
    private const LAYERS = [
        'Domain',
        'Application',
        'Infrastructure',
        'Interface',
        'Providers',
        'Public',
    ];

    private const DOMAIN_FORBIDDEN_IMPORT_PREFIXES = [
        'Illuminate\\',
        'Laravel\\',
        'Symfony\\',
        'App\\Models\\',
        'App\\Services\\',
        'App\\Http\\',
        'DB',
        'Cache',
        'Request',
        'Response',
    ];

    private const APPLICATION_FORBIDDEN_IMPORT_FRAGMENTS = [
        '\\Infrastructure\\',
        '\\Interface\\',
        '\\Http\\Controllers\\',
        '\\Http\\Requests\\',
        '\\Jobs\\',
        '\\Observers\\',
    ];

    /**
     * @param  string[]  $moduleRoots
     */
    public function analyze(string $projectRoot, array $moduleRoots = ['modules']): DddAnalysisResult
    {
        $modules = [];
        $issues = [];

        foreach ($moduleRoots as $moduleRoot) {
            $root = $this->absolutePath($projectRoot, $moduleRoot);
            if (! is_dir($root)) {
                continue;
            }

            foreach ($this->moduleDirectories($root) as $modulePath) {
                $module = $this->analyzeModule($projectRoot, $modulePath);
                $modules[] = $module;
                array_push($issues, ...$module->issues);
            }
        }

        return new DddAnalysisResult($modules, $issues);
    }

    private function analyzeModule(string $projectRoot, string $modulePath): DddModule
    {
        $moduleName = basename($modulePath);
        $appPath = $modulePath.'/app';
        $layerCounts = [];
        $issues = [];

        foreach (self::LAYERS as $layer) {
            $layerPath = $appPath.'/'.$layer;
            $files = is_dir($layerPath) ? $this->phpFiles($layerPath) : [];
            $layerCounts[$layer] = count($files);

            foreach ($files as $file) {
                array_push($issues, ...$this->analyzeLayerFile($projectRoot, $moduleName, $layer, $file));
            }
        }

        if (is_dir($appPath)) {
            foreach ($this->phpFiles($appPath) as $file) {
                $relative = $this->relativePath($modulePath, $file);
                if (! $this->isInKnownLayer($relative)) {
                    $issues[] = $this->issue(
                        'DDD_UNKNOWN_LAYER',
                        'medium',
                        $moduleName,
                        'app',
                        'PHP file under module app/ is not inside a known DDD layer.',
                        $projectRoot,
                        $file,
                    );
                }
            }
        }

        return new DddModule(
            name: $moduleName,
            path: $this->relativePath($projectRoot, $modulePath),
            layerFileCounts: $layerCounts,
            issues: $issues,
        );
    }

    /**
     * @return list<DddIssue>
     */
    private function analyzeLayerFile(string $projectRoot, string $moduleName, string $layer, string $file): array
    {
        $source = (string) file_get_contents($file);
        $imports = $this->imports($source);
        $issues = [];

        if ($layer === 'Domain') {
            foreach ($imports as $import) {
                if ($this->startsWithAny($import, self::DOMAIN_FORBIDDEN_IMPORT_PREFIXES)) {
                    $issues[] = $this->issue(
                        'DDD_DOMAIN_FORBIDDEN_IMPORT',
                        'high',
                        $moduleName,
                        $layer,
                        "Domain layer imports framework/legacy dependency `{$import}`.",
                        $projectRoot,
                        $file,
                        $this->lineFor($source, $import),
                    );
                }
            }
        }

        if ($layer === 'Application') {
            foreach ($imports as $import) {
                if ($this->containsAny($import, self::APPLICATION_FORBIDDEN_IMPORT_FRAGMENTS)
                    || str_starts_with($import, "App\\Modules\\{$this->studly($moduleName)}\\Infrastructure\\")
                    || str_starts_with($import, "App\\Modules\\{$this->studly($moduleName)}\\Interface\\")
                ) {
                    $issues[] = $this->issue(
                        'DDD_APPLICATION_FORBIDDEN_IMPORT',
                        'high',
                        $moduleName,
                        $layer,
                        "Application layer imports Interface/Infrastructure dependency `{$import}`.",
                        $projectRoot,
                        $file,
                        $this->lineFor($source, $import),
                    );
                }
            }
        }

        if ($layer === 'Public' && str_contains(str_replace('\\', '/', $file), '/Public/Contracts/')) {
            if (! preg_match('/\binterface\s+[A-Za-z_][A-Za-z0-9_]*/', $source)) {
                $issues[] = $this->issue(
                    'DDD_PUBLIC_CONTRACT_NOT_INTERFACE',
                    'high',
                    $moduleName,
                    $layer,
                    'Public/Contracts files must declare interfaces.',
                    $projectRoot,
                    $file,
                );
            }

            foreach ($imports as $import) {
                if (str_starts_with($import, 'App\\Models\\')) {
                    $issues[] = $this->issue(
                        'DDD_PUBLIC_CONTRACT_IMPORTS_MODEL',
                        'high',
                        $moduleName,
                        $layer,
                        "Public Contract imports Eloquent model `{$import}`.",
                        $projectRoot,
                        $file,
                        $this->lineFor($source, $import),
                    );
                }
            }
        }

        if ($layer === 'Public' && str_contains(str_replace('\\', '/', $file), '/Public/Events/')) {
            $class = $this->declaredClassName($source);
            if ($class !== null && ! preg_match('/V\d+$/', $class)) {
                $issues[] = $this->issue(
                    'DDD_PUBLIC_EVENT_NOT_VERSIONED',
                    'medium',
                    $moduleName,
                    $layer,
                    "Public event `{$class}` must end with a version suffix like V1.",
                    $projectRoot,
                    $file,
                );
            }
        }

        if ($layer === 'Public' && str_contains(str_replace('\\', '/', $file), '/Public/DTO')) {
            if (preg_match('/\bclass\s+[A-Za-z_][A-Za-z0-9_]*/', $source)
                && ! preg_match('/\breadonly\s+class\s+[A-Za-z_][A-Za-z0-9_]*/', $source)
            ) {
                $issues[] = $this->issue(
                    'DDD_PUBLIC_DTO_NOT_READONLY',
                    'medium',
                    $moduleName,
                    $layer,
                    'Public DTO classes should be readonly.',
                    $projectRoot,
                    $file,
                );
            }
        }

        return $issues;
    }

    /**
     * @return string[]
     */
    private function imports(string $source): array
    {
        preg_match_all('/^\s*use\s+([^;]+);/m', $source, $matches);

        return array_values(array_filter(array_map(
            static fn (string $import): string => trim(explode(' as ', $import)[0]),
            $matches[1],
        )));
    }

    private function declaredClassName(string $source): ?string
    {
        if (preg_match('/\b(?:readonly\s+)?(?:final\s+)?class\s+([A-Za-z_][A-Za-z0-9_]*)/', $source, $matches)) {
            return $matches[1];
        }

        return null;
    }

    private function issue(
        string $rule,
        string $severity,
        string $module,
        string $layer,
        string $message,
        string $projectRoot,
        string $file,
        ?int $line = null,
    ): DddIssue {
        $relative = $this->relativePath($projectRoot, $file);

        return new DddIssue(
            id: 'ddd::'.md5($rule.'|'.$relative.'|'.($line ?? 0).'|'.$message),
            rule: $rule,
            severity: $severity,
            module: $module,
            layer: $layer,
            message: $message,
            file: $relative,
            line: $line,
        );
    }

    /**
     * @return string[]
     */
    private function moduleDirectories(string $root): array
    {
        $dirs = [];
        foreach (glob($root.'/*', GLOB_ONLYDIR) ?: [] as $dir) {
            if (is_dir($dir.'/app') || file_exists($dir.'/composer.json') || file_exists($dir.'/MIGRATION_PLAN.md')) {
                $dirs[] = $dir;
            }
        }
        sort($dirs);

        return $dirs;
    }

    /**
     * @return string[]
     */
    private function phpFiles(string $dir): array
    {
        $files = [];
        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($dir, \FilesystemIterator::SKIP_DOTS),
        );

        foreach ($iterator as $file) {
            if ($file->getExtension() === 'php') {
                $files[] = $file->getPathname();
            }
        }
        sort($files);

        return $files;
    }

    private function absolutePath(string $projectRoot, string $path): string
    {
        if (str_starts_with($path, '/')) {
            return rtrim($path, '/');
        }

        return rtrim($projectRoot, '/').'/'.trim($path, '/');
    }

    private function relativePath(string $base, string $path): string
    {
        $base = rtrim(str_replace('\\', '/', $base), '/').'/';
        $path = str_replace('\\', '/', $path);

        return str_starts_with($path, $base) ? substr($path, strlen($base)) : $path;
    }

    private function isInKnownLayer(string $relativePath): bool
    {
        $relativePath = str_replace('\\', '/', $relativePath);
        foreach (self::LAYERS as $layer) {
            if (str_starts_with($relativePath, 'app/'.$layer.'/')) {
                return true;
            }
        }

        return false;
    }

    private function startsWithAny(string $value, array $prefixes): bool
    {
        foreach ($prefixes as $prefix) {
            if (str_starts_with($value, $prefix)) {
                return true;
            }
        }

        return false;
    }

    private function containsAny(string $value, array $needles): bool
    {
        foreach ($needles as $needle) {
            if (str_contains($value, $needle)) {
                return true;
            }
        }

        return false;
    }

    private function lineFor(string $source, string $needle): ?int
    {
        $lines = explode("\n", $source);
        foreach ($lines as $index => $line) {
            if (str_contains($line, $needle)) {
                return $index + 1;
            }
        }

        return null;
    }

    private function studly(string $value): string
    {
        $value = str_replace(['-', '_'], ' ', $value);

        return str_replace(' ', '', ucwords($value));
    }
}
