#Requires -Version 7.3
param([string]$Repository = 'gitedmond/aletheia')
$ErrorActionPreference = 'Stop'
$raw = & gh pr list --repo $Repository --state open --limit 100 --json number,title,headRefOid,statusCheckRollup
if ($LASTEXITCODE -ne 0) { throw 'Cannot read pull requests' }
$prs = @($raw | ConvertFrom-Json)
if ($prs.Count -eq 0) { Write-Output 'No open pull requests'; exit 0 }
$parts = $Repository.Split('/')
if ($parts.Count -ne 2 -or $Repository -notmatch '^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$') { throw 'Expected owner/repository' }
$fields = ($prs | ForEach-Object { 'p' + $_.number + ':pullRequest(number:' + $_.number + '){reviewThreads(first:100){pageInfo{hasNextPage} nodes{isResolved}} commits(last:1){nodes{commit{status{contexts{context description}}}}}}' }) -join ' '
$query = 'query{repository(owner:"' + $parts[0] + '",name:"' + $parts[1] + '"){' + $fields + '}}'
$raw = & gh api graphql -f "query=$query"
if ($LASTEXITCODE -ne 0) { throw 'Cannot read review threads' }
$reviews = ($raw | ConvertFrom-Json).data.repository
foreach ($pr in $prs) {
    $threads = $reviews.('p' + $pr.number).reviewThreads
    $unresolved = @($threads.nodes | Where-Object { -not $_.isResolved }).Count
    $checks = @($pr.statusCheckRollup | ForEach-Object {
        $name = if ($_.name) { $_.name } else { $_.context }
        $state = if ($_.conclusion) { $_.conclusion } elseif ($_.state) { $_.state } else { $_.status }
        $context = @($reviews.('p' + $pr.number).commits.nodes[0].commit.status.contexts | Where-Object { $_.context -eq $name })
        if ($context.description -match 'Review skipped') { $state = 'SKIPPED' }
        "$name=$state"
    }) -join ', '
    [pscustomobject]@{ PR = $pr.number; Head = $pr.headRefOid.Substring(0,7); ReviewsOpen = $unresolved; MoreThreads = $threads.pageInfo.hasNextPage; Checks = $checks }
}
