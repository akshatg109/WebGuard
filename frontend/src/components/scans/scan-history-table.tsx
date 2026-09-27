"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import {
  flexRender,
  getCoreRowModel,
  getFilteredRowModel,
  getPaginationRowModel,
  getSortedRowModel,
  useReactTable,
  type ColumnDef,
  type Column,
  type SortingState,
} from "@tanstack/react-table";
import { ArrowDown, ArrowUp, ArrowUpDown, ChevronLeft, ChevronRight, ExternalLink, Search } from "lucide-react";
import { EmptyState } from "@/components/shared/empty-state";
import { ScanStatusBadge } from "@/components/shared/scan-status-badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { ScanListItem } from "@/data/scan-preview";

export function ScanHistoryTable({ data }: { data: ScanListItem[] }) {
  const [sorting, setSorting] = useState<SortingState>([{ id: "createdAt", desc: true }]);
  const [globalFilter, setGlobalFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const filteredData = useMemo(
    () => statusFilter === "all" ? data : data.filter((scan) => scan.status === statusFilter),
    [data, statusFilter],
  );
  const columns = useMemo<ColumnDef<ScanListItem>[]>(() => [
    {
      accessorKey: "targetUrl",
      header: ({ column }) => <SortableHeader column={column} label="Target" />,
      cell: ({ row }) => (
        <span className="block max-w-[240px] truncate font-mono text-xs text-foreground" title={row.original.targetUrl}>
          {row.original.targetUrl}
        </span>
      ),
    },
    {
      accessorKey: "createdAt",
      header: ({ column }) => <SortableHeader column={column} label="Scan date" />,
      cell: ({ row }) => <span className="text-xs text-muted-foreground">{formatDate(row.original.createdAt)}</span>,
    },
    {
      accessorKey: "status",
      header: "Status",
      cell: ({ row }) => <ScanStatusBadge status={row.original.status} />,
    },
    {
      accessorKey: "score",
      header: ({ column }) => <SortableHeader column={column} label="Score" align="right" />,
      cell: ({ row }) => <span className="block text-right font-mono text-xs tabular-nums text-muted-foreground">{row.original.score ?? "—"}</span>,
    },
    {
      accessorKey: "findingCount",
      header: ({ column }) => <SortableHeader column={column} label="Findings" align="right" />,
      cell: ({ row }) => <span className="block text-right font-mono text-xs tabular-nums text-muted-foreground">{row.original.findingCount ?? "—"}</span>,
    },
    {
      id: "action",
      header: () => <span className="sr-only">Actions</span>,
      enableSorting: false,
      cell: ({ row }) => (
        <Button aria-label={`View report for ${row.original.targetUrl}`} render={<Link href={`/scans/${row.original.id}`} />} size="icon-sm" variant="ghost">
          <ExternalLink aria-hidden="true" />
        </Button>
      ),
    },
  ], []);

  // TanStack's table instance exposes callbacks that React Compiler intentionally does not memoize.
  // eslint-disable-next-line react-hooks/incompatible-library
  const table = useReactTable({
    data: filteredData,
    columns,
    state: { sorting, globalFilter },
    onSortingChange: setSorting,
    onGlobalFilterChange: setGlobalFilter,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
    globalFilterFn: "includesString",
    initialState: { pagination: { pageSize: 8 } },
  });
  const isEmpty = table.getRowModel().rows.length === 0;

  return (
    <Card className="border-border/70 bg-card/80 shadow-none">
      <CardContent className="space-y-4 p-4 sm:p-5">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="relative w-full sm:max-w-xs">
            <Search aria-hidden="true" className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              aria-label="Search scan history by target"
              className="h-10 pl-9"
              onChange={(event) => setGlobalFilter(event.target.value)}
              placeholder="Search targets…"
              value={globalFilter}
            />
          </div>
          <div className="flex items-center gap-2">
            <label className="text-xs text-muted-foreground" htmlFor="scan-status-filter">Status</label>
            <select
              className="h-9 rounded-lg border border-input bg-background px-3 text-xs text-foreground outline-none focus-visible:ring-2 focus-visible:ring-ring"
              id="scan-status-filter"
              onChange={(event) => setStatusFilter(event.target.value)}
              value={statusFilter}
            >
              <option value="all">All statuses</option>
              <option value="completed">Completed</option>
              <option value="running">Running</option>
              <option value="failed">Failed</option>
            </select>
          </div>
        </div>

        {isEmpty ? (
          <div className="rounded-lg border border-border/60 bg-background/20 p-3 sm:p-5">
            <EmptyState
              compact
              description={globalFilter || statusFilter !== "all"
                ? "No scan rows match these filters. Clear the filters to see the current scan history."
                : "No live scan records are connected to this preview. This table will show your own scan history when the API is integrated."}
              title={globalFilter || statusFilter !== "all" ? "No matching scans" : "No scan history yet"}
              action={(globalFilter || statusFilter !== "all") ? (
                <Button onClick={() => { setGlobalFilter(""); setStatusFilter("all"); }} size="sm" variant="outline">Clear filters</Button>
              ) : undefined}
            />
          </div>
        ) : (
          <>
            <div className="hidden overflow-hidden rounded-lg border border-border/70 md:block">
              <Table>
                <caption className="sr-only">Scan history with target, scan date, status, score, and finding count</caption>
                <TableHeader className="bg-muted/35">
                  {table.getHeaderGroups().map((group) => (
                    <TableRow key={group.id}>
                      {group.headers.map((header) => {
                        const order = header.column.getIsSorted();
                        return (
                          <TableHead
                            aria-sort={order ? order === "asc" ? "ascending" : "descending" : "none"}
                            className={header.id === "score" || header.id === "findingCount" ? "text-right" : undefined}
                            key={header.id}
                          >
                            {header.isPlaceholder ? null : flexRender(header.column.columnDef.header, header.getContext())}
                          </TableHead>
                        );
                      })}
                    </TableRow>
                  ))}
                </TableHeader>
                <TableBody>
                  {table.getRowModel().rows.map((row) => (
                    <TableRow key={row.id}>
                      {row.getVisibleCells().map((cell) => <TableCell key={cell.id}>{flexRender(cell.column.columnDef.cell, cell.getContext())}</TableCell>)}
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
            <div className="space-y-2 md:hidden">
              {table.getRowModel().rows.map((row) => (
                <article className="rounded-lg border border-border/70 bg-background/25 p-4" key={row.id}>
                  <div className="flex items-start justify-between gap-3">
                    <span className="min-w-0 break-all font-mono text-xs text-foreground">{row.original.targetUrl}</span>
                    <ScanStatusBadge status={row.original.status} />
                  </div>
                  <div className="mt-3 flex items-center justify-between text-[11px] text-muted-foreground">
                    <span>{formatDate(row.original.createdAt)}</span>
                    <span>Score {row.original.score ?? "—"}</span>
                    <span>Findings {row.original.findingCount ?? "—"}</span>
                    <Button aria-label={`View report for ${row.original.targetUrl}`} render={<Link href={`/scans/${row.original.id}`} />} size="icon-sm" variant="ghost">
                      <ExternalLink aria-hidden="true" />
                    </Button>
                  </div>
                </article>
              ))}
            </div>
            <div className="flex items-center justify-between border-t border-border/60 pt-3">
              <p aria-live="polite" className="text-[11px] text-muted-foreground">
                {table.getFilteredRowModel().rows.length} scan records
              </p>
              <div className="flex items-center gap-1">
                <Button aria-label="Previous scan history page" disabled={!table.getCanPreviousPage()} onClick={() => table.previousPage()} size="icon-sm" variant="outline">
                  <ChevronLeft aria-hidden="true" />
                </Button>
                <span className="px-2 text-[11px] tabular-nums text-muted-foreground">{table.getState().pagination.pageIndex + 1} / {table.getPageCount()}</span>
                <Button aria-label="Next scan history page" disabled={!table.getCanNextPage()} onClick={() => table.nextPage()} size="icon-sm" variant="outline">
                  <ChevronRight aria-hidden="true" />
                </Button>
              </div>
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}

function SortableHeader({
  column,
  label,
  align = "left",
}: {
  column: Column<ScanListItem, unknown>;
  label: string;
  align?: "left" | "right";
}) {
  const sorted = column.getIsSorted();
  const Icon = sorted === "asc" ? ArrowUp : sorted === "desc" ? ArrowDown : ArrowUpDown;
  return (
    <button
      aria-label={`Sort by ${label}${sorted ? `, currently ${sorted === "asc" ? "ascending" : "descending"}` : ""}`}
      className={`inline-flex items-center gap-1.5 rounded-sm text-[10px] font-semibold tracking-wide text-muted-foreground uppercase hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring ${align === "right" ? "ml-auto" : ""}`}
      onClick={column.getToggleSortingHandler()}
      type="button"
    >
      {label}<Icon aria-hidden="true" className="size-3" />
    </button>
  );
}

function formatDate(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : new Intl.DateTimeFormat("en", { dateStyle: "medium" }).format(date);
}
