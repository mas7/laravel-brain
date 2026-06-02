<?php

use LaraMint\LaravelBrain\Analysis\DddModuleAnalyzer;
use LaraMint\LaravelBrain\Graph\GraphSplitter;

function dddWriteFile(string $path, string $contents): void
{
    $dir = dirname($path);
    if (! is_dir($dir)) {
        mkdir($dir, 0777, true);
    }
    file_put_contents($path, $contents);
}

function dddTempProject(): string
{
    $dir = sys_get_temp_dir().'/laravel-brain-ddd-'.bin2hex(random_bytes(5));
    mkdir($dir, 0777, true);

    return $dir;
}

it('detects DDD modules and flags layer boundary violations', function () {
    $root = dddTempProject();

    dddWriteFile($root.'/modules/identity/app/Domain/Entities/User.php', <<<'PHP'
<?php
namespace App\Modules\Identity\Domain\Entities;
use Illuminate\Database\Eloquent\Model;
final class User {}
PHP);

    dddWriteFile($root.'/modules/identity/app/Application/UseCases/Login.php', <<<'PHP'
<?php
namespace App\Modules\Identity\Application\UseCases;
use App\Modules\Identity\Infrastructure\Persistence\EloquentUserRepository;
final class Login {}
PHP);

    dddWriteFile($root.'/modules/identity/app/Public/Contracts/AuthApi.php', <<<'PHP'
<?php
namespace App\Modules\Identity\Public\Contracts;
use App\Models\User;
final class AuthApi {}
PHP);

    dddWriteFile($root.'/modules/identity/app/Public/Events/UserRegistered.php', <<<'PHP'
<?php
namespace App\Modules\Identity\Public\Events;
final readonly class UserRegistered {}
PHP);

    dddWriteFile($root.'/modules/identity/app/Public/DTO/UserReference.php', <<<'PHP'
<?php
namespace App\Modules\Identity\Public\DTO;
final class UserReference {}
PHP);

    dddWriteFile($root.'/modules/identity/app/LooseFile.php', <<<'PHP'
<?php
namespace App\Modules\Identity;
final class LooseFile {}
PHP);

    $result = (new DddModuleAnalyzer)->analyze($root);

    expect($result->moduleCount())->toBe(1)
        ->and($result->issueCount())->toBe(7);

    $rules = array_map(static fn ($issue) => $issue->rule, $result->issues);

    expect($rules)->toContain('DDD_DOMAIN_FORBIDDEN_IMPORT')
        ->and($rules)->toContain('DDD_APPLICATION_FORBIDDEN_IMPORT')
        ->and($rules)->toContain('DDD_PUBLIC_CONTRACT_NOT_INTERFACE')
        ->and($rules)->toContain('DDD_PUBLIC_CONTRACT_IMPORTS_MODEL')
        ->and($rules)->toContain('DDD_PUBLIC_EVENT_NOT_VERSIONED')
        ->and($rules)->toContain('DDD_PUBLIC_DTO_NOT_READONLY')
        ->and($rules)->toContain('DDD_UNKNOWN_LAYER');
});

it('builds a DDD modules graph tab', function () {
    $root = dddTempProject();

    dddWriteFile($root.'/modules/billing/app/Domain/Entities/Invoice.php', <<<'PHP'
<?php
namespace App\Modules\Billing\Domain\Entities;
final class Invoice {}
PHP);

    $result = (new DddModuleAnalyzer)->analyze($root);
    $tab = (new GraphSplitter)->buildDddTab($result, 'Test App', '2026-06-01T00:00:00Z');

    expect($tab)->not->toBeNull()
        ->and($tab['id'])->toBe('ddd--modules')
        ->and($tab['manifest']->category)->toBe('DDD')
        ->and($tab['manifest']->label)->toBe('DDD Modules')
        ->and($tab['graph']->nodeCount())->toBeGreaterThan(1);
});

it('builds a focused DDD graph tab for each module', function () {
    $root = dddTempProject();

    dddWriteFile($root.'/modules/billing/app/Domain/Entities/Invoice.php', <<<'PHP'
<?php
namespace App\Modules\Billing\Domain\Entities;
final class Invoice {}
PHP);

    dddWriteFile($root.'/modules/identity/app/Domain/Entities/User.php', <<<'PHP'
<?php
namespace App\Modules\Identity\Domain\Entities;
final class User {}
PHP);

    $result = (new DddModuleAnalyzer)->analyze($root);
    $tabs = (new GraphSplitter)->buildDddModuleTabs($result, 'Test App', '2026-06-01T00:00:00Z');

    expect($tabs)->toHaveCount(2)
        ->and(array_map(static fn ($tab) => $tab['manifest']->label, $tabs))
        ->toBe(['billing', 'identity'])
        ->and(array_map(static fn ($tab) => $tab['manifest']->category, $tabs))
        ->toBe(['DDD', 'DDD'])
        ->and(array_map(static fn ($tab) => $tab['graph']->nodeCount(), $tabs))
        ->each->toBeGreaterThan(1);
});
