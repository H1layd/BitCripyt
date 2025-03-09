import matplotlib.pyplot as plt
import pandas as pd
from pymodbus.client.sync import ModbusTcpClient

# Настройки подключения
IP_ADDRESS = '192.168.1.1'  # Укажите IP-адрес вашего устройства
START_REGISTER = 0           # Начальный регистр
REGISTER_COUNT = 10          # Количество регистров для чтения

def read_modbus_data(ip, start_register, count):
    client = ModbusTcpClient(ip)
    client.connect()
    result = client.read_holding_registers(start_register, count)
    client.close()
    
    if result.isError():
        print("Ошибка чтения данных:", result)
        return None
    return result.registers

def plot_data(data):
    plt.plot(data)
    plt.title('Данные с устройства')
    plt.xlabel('Индекс')
    plt.ylabel('Значение')
    plt.grid()
    plt.show()

def export_to_excel(data, filename):
    df = pd.DataFrame(data, columns=['Значение'])
    df.to_excel(filename, index=False)
    print(f"Данные успешно экспортированы в {filename}")

def main():
    data = read_modbus_data(IP_ADDRESS, START_REGISTER, REGISTER_COUNT)
    if data is not None:
        plot_data(data)
        export_to_excel(data, 'output.xlsx')

if __name__ == "__main__":
    main()