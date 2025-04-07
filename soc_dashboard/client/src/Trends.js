import React from 'react';
import { Line } from 'react-chartjs-2';

const Trends = () => {
    const data = {
        labels: ['January', 'February', 'March', 'April', 'May', 'June', 'July'],
        datasets: [
            {
                label: 'Attack Frequency',
                data: [65, 59, 80, 81, 56, 55, 40],
                fill: false,
                backgroundColor: 'rgb(75, 192, 192)',
                borderColor: 'rgba(75, 192, 192, 0.2)',
            },
        ],
    };

    return (
        <div>
            <h1>Attack Trends</h1>
            <Line data={data} />
        </div>
    );
};

export default Trends;