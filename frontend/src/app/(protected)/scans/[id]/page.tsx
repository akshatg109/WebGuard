import { ScanReportView } from "@/components/scans/scan-report-view";

type ScanDetailsProps = { params: Promise<{ id: string }> };

export default async function ScanDetailsPage({ params }: ScanDetailsProps) {
  const { id } = await params;
  return <ScanReportView scanId={id} />;
}
