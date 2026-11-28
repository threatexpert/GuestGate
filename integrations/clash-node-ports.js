function main(config) {
  const startPort = 18901;
  const nodes = config.proxies || [];
  if (nodes.length === 0) return config;

  const mainGroup = "主出口";
  const autoGroup = "全部节点自动优选";
  const portGroup = "端口对照";
  const names = nodes.map(node => node.name);

  const listeners = nodes.map((node, index) => {
    const port = startPort + index;
    return {
      name: `node-port-${port}`,
      type: "mixed",
      listen: "127.0.0.1",
      port,
      proxy: node.name
    };
  });

  const portRows = listeners.map(({ port, proxy }) => ({
    name: `${port} | ${proxy}`,
    type: "select",
    proxies: [proxy],
    hidden: true
  }));

  config.listeners = [...(config.listeners || []), ...listeners];

  config["proxy-groups"] = [
    ...(config["proxy-groups"] || []),
    {
      name: mainGroup,
      type: "select",
      proxies: [autoGroup, ...names]
    },
    {
      name: autoGroup,
      type: "url-test",
      proxies: names,
      url: "https://www.gstatic.com/generate_204",
      interval: 300,
      lazy: false,
      tolerance: 0,
      "expected-status": 204
    },
    {
      name: portGroup,
      type: "select",
      proxies: portRows.map(row => row.name)
    },
    ...portRows
  ];

  config.rules = [`MATCH,${mainGroup}`];
  return config;
}