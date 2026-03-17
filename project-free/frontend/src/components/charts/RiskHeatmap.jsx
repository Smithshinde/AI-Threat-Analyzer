const LIKELIHOOD = ['rare','unlikely','possible','likely','almost_certain'];
const IMPACT     = ['negligible','minor','moderate','major','critical'];

function cellColor(l, i) {
  const score = (LIKELIHOOD.indexOf(l) + 1) * (IMPACT.indexOf(i) + 1);
  if (score >= 15) return 'bg-red-500 text-white';
  if (score >= 9)  return 'bg-orange-400 text-white';
  if (score >= 4)  return 'bg-yellow-300 text-gray-800';
  return 'bg-green-300 text-gray-800';
}

export default function RiskHeatmap({ data = {} }) {
  return (
    <div className="overflow-x-auto">
      <table className="text-xs border-collapse w-full">
        <thead>
          <tr>
            <th className="p-2 text-left text-gray-500 font-medium w-24">L\I</th>
            {IMPACT.map(i => (
              <th key={i} className="p-2 text-center text-gray-600 font-medium capitalize">{i}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {[...LIKELIHOOD].reverse().map(l => (
            <tr key={l}>
              <td className="p-2 text-gray-600 font-medium capitalize text-right pr-3">{l.replace('_',' ')}</td>
              {IMPACT.map(i => {
                const count = data[`${l}:${i}`] || 0;
                return (
                  <td key={i} className={`${cellColor(l, i)} p-3 text-center rounded m-0.5 cursor-default font-bold`}>
                    {count > 0 ? count : ''}
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
      <div className="flex items-center gap-4 mt-3 text-xs text-gray-500">
        <span className="flex items-center gap-1"><span className="w-3 h-3 bg-green-300 rounded-sm inline-block"/>Low</span>
        <span className="flex items-center gap-1"><span className="w-3 h-3 bg-yellow-300 rounded-sm inline-block"/>Medium</span>
        <span className="flex items-center gap-1"><span className="w-3 h-3 bg-orange-400 rounded-sm inline-block"/>High</span>
        <span className="flex items-center gap-1"><span className="w-3 h-3 bg-red-500 rounded-sm inline-block"/>Critical</span>
      </div>
    </div>
  );
}
