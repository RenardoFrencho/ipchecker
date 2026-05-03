import argparse
import asyncio
import ipaddress
import platform
import sys
from concurrent.futures import ProcessPoolExecutor

import aiohttp
import geoip2.database
from loguru import logger

URL = "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/main/cidrwhitelist.txt"
GEOIP_COUNTRY_DB = "GeoLite2-Country.mmdb"
GEOIP_ASN_DB = "GeoLite2-ASN.mmdb"

logger.remove()
logger.add(
    sys.stderr,
    format="<level>{level: <8}</level> | <cyan>{time:HH:mm:ss}</cyan> | {message}",
    level="DEBUG",
)


async def ping_ip(ip):
    try:
        conn = asyncio.open_connection(ip, 443)
        _, writer = await asyncio.wait_for(conn, timeout=1.5)
        writer.close()
        await writer.wait_closed()
        logger.debug(f"TCPing SUCCESS: {ip}")
        return True
    except:
        logger.trace(f"TCPing FAIL: {ip}")
        return False


async def fetch_cidrs():
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(URL) as response:
                response.raise_for_status()
                text = await response.text()
                lines = [line.strip() for line in text.splitlines() if line.strip()]
                logger.info(f"Загружено {len(lines)} строк из удаленного репозитория")
                return lines
    except Exception as e:
        logger.error(f"Ошибка при загрузке URL: {e}")
        return []


def get_geo_info(ip, country_reader, asn_reader):
    try:
        c_res = country_reader.country(ip)
        a_res = asn_reader.asn(ip)
        return {
            "country": c_res.country.iso_code,
            "isp": a_res.autonomous_system_organization,
            "as": f"AS{a_res.autonomous_system_number}",
        }
    except Exception as e:
        logger.trace(f"GeoIP info not found for {ip}: {e}")
        return None


async def process_line(line, country_reader, asn_reader, mode):
    try:
        raw_line = line.strip()
        if "|" in raw_line:
            cidr = raw_line.split("|")[0].strip()
        else:
            cidr = raw_line

        network = ipaddress.ip_network(cidr, strict=False)
        ip = str(network[0])

        if mode == "parse":
            info = get_geo_info(ip, country_reader, asn_reader)
            if info:
                if info["country"] != "RU":
                    res = f"{cidr} | {info['country']} | {info['isp']} | {info['as']}"
                    logger.info(f"MATCH (non-RU): {res}")
                    return res
                else:
                    logger.trace(f"SKIP (RU): {cidr}")
            return None

        elif mode == "ping":
            is_alive = await ping_ip(ip)
            if is_alive:
                logger.success(f"ALIVE: {raw_line}")
                return raw_line
            return None

    except Exception as e:
        logger.error(f"Ошибка обработки строки '{line}': {e}")
    return None


async def main():
    parser = argparse.ArgumentParser(description="Асинхронный GeoIP парсер и Пингер")
    parser.add_argument("--mode", choices=["parse", "ping"], required=True)
    parser.add_argument("--input", type=str)
    parser.add_argument("--output", type=str, default="results.txt")
    parser.add_argument("--concurrency", type=int, default=100)

    args = parser.parse_args()

    if args.mode == "parse":
        logger.info("Запуск режима PARSE")
        cidrs = await fetch_cidrs()
    else:
        if not args.input:
            logger.error("Для режима ping укажите файл через --input")
            return
        try:
            with open(args.input, "r", encoding="utf-8") as f:
                cidrs = [
                    l for l in f.readlines() if l.strip() and not l.startswith("CIDR")
                ]
            logger.info(f"Загружено {len(cidrs)} строк из файла {args.input}")
        except Exception as e:
            logger.error(f"Не удалось прочитать файл: {e}")
            return

    c_reader = asn_reader = None
    if args.mode == "parse":
        try:
            c_reader = geoip2.database.Reader(GEOIP_COUNTRY_DB)
            asn_reader = geoip2.database.Reader(GEOIP_ASN_DB)
        except Exception as e:
            logger.error(f"Ошибка загрузки GeoIP баз: {e}")
            return

    semaphore = asyncio.Semaphore(args.concurrency)

    async def sem_task(line):
        async with semaphore:
            return await process_line(line, c_reader, asn_reader, args.mode)

    logger.info(f"Начинаю асинхронную обработку (потоков: {args.concurrency})...")
    tasks = [sem_task(line) for line in cidrs]

    results = await asyncio.gather(*tasks)
    final_results = [r for r in results if r]

    if final_results:
        with open(args.output, "w", encoding="utf-8") as f:
            for r in final_results:
                f.write(r + "\n")
        logger.success(
            f"Завершено! Сохранено {len(final_results)} активных записей в {args.output}"
        )
    else:
        logger.warning(
            "Результатов нет. Список пуст или ни один узел не ответил на пинг."
        )

    if c_reader:
        c_reader.close()
    if asn_reader:
        asn_reader.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.warning("Прервано пользователем")
