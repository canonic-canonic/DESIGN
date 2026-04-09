import { ChannelView } from "./ChannelView";
import { TalkView } from "./TalkView";

export function generateStaticParams() {
  return [
    { channel: "talk" },
    { channel: "general" },
    { channel: "now-playing" },
    { channel: "artist-talk" },
    { channel: "riddim-tracing" },
    { channel: "feedback" },
  ];
}

export default function ChannelPage({ params }: { params: { channel: string } }) {
  if (params.channel === "talk") return <TalkView />;
  return <ChannelView channel={params.channel} />;
}
