import { RadialBarChart, RadialBar, Legend, ResponsiveContainer, PieChart, Pie, Cell, Tooltip } from 'recharts';

const COLORS = ['#22c55e','#eab308','#ef4444','#9ca3af'];

export function ComplianceRadial({ score, framework }) {
  const data = [{ name: 'Score', value: score, fill: score >= 80 ? '#22c55e' : score >= 60 ? '#eab308' : '#ef4444' }];
  return (
    <div className="flex flex-col items-center">
      <ResponsiveContainer width="100%" height={160}>
        <RadialBarChart innerRadius="60%" outerRadius="90%" data={data} startAngle={225} endAngle={-45}>
          <RadialBar dataKey="value" background={{ fill: '#f1f5f9' }}/>
        </RadialBarChart>
      </ResponsiveContainer>
      <div className="text-center -mt-14">
        <p className="text-3xl font-bold text-gray-900">{score}%</p>
        <p className="text-xs text-gray-500 mt-1">{framework}</p>
      </div>
    </div>
  );
}

export function CompliancePie({ data }) {
  const chartData = [
    { name: 'Compliant',     value: data?.compliant    || 0 },
    { name: 'Partial',       value: data?.partial      || 0 },
    { name: 'Non-Compliant', value: data?.non_compliant|| 0 },
    { name: 'Not Assessed',  value: data?.not_assessed || 0 },
  ].filter(d => d.value > 0);

  return (
    <ResponsiveContainer width="100%" height={200}>
      <PieChart>
        <Pie data={chartData} innerRadius={55} outerRadius={80} paddingAngle={3} dataKey="value">
          {chartData.map((_, i) => <Cell key={i} fill={COLORS[i]}/>)}
        </Pie>
        <Tooltip formatter={(v, n) => [v, n]}/>
        <Legend wrapperStyle={{ fontSize: '11px' }}/>
      </PieChart>
    </ResponsiveContainer>
  );
}
